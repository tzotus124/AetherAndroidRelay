# WoL Host - install on the PC you want to wake AND stream from remotely (run once, as Administrator).
# Sets up Tailscale + Sunshine (game-stream host, starts at boot even on the sign-in screen) for Moonlight clients.
# pip install customtkinter (GUI only; the background agent needs just the standard library)   |   exe: see build_exe.bat
# Last tab "TimeGuard": TimeGuard (its whole source is embedded at the bottom of this file; needs  pip install PySide6) runs INSIDE this window (same process, a real Qt child widget).
# The window itself is Qt (QtWebEngine). Old WebView2 window: --webview2 ; old Tk window: --classic. An .exe build contains both.
import datetime, hashlib, math, pathlib, site, tempfile, traceback     # used by the embedded TimeGuard source (listed here so PyInstaller bundles them)
import base64, ctypes, importlib.util, json, os, re, secrets, shutil, socket, ssl, subprocess, sys, threading, time, urllib.error, urllib.request
HPORT = 48998
NOWIN = {"creationflags": 0x08000000} if os.name == "nt" else {}
def _run(*a, **k): return subprocess.run(*a, **NOWIN, **k)
def sh(cmd, timeout=180):
    try: r = _run(cmd, shell=True, capture_output=True, text=True, timeout=timeout); return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e: return 1, str(e)
def ps(cmd): 
    try: r = _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], capture_output=True, text=True, timeout=120); return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e: return 1, str(e)
def is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False
# Opening WoL Host asks Windows (UAC) for administrator rights by itself, right at the start, before anything else is loaded. The background helpers
# (agent, TimeGuard parts, input / Sunshine helpers) are started by the program itself, as SYSTEM or as the user, and must never be restarted elevated.
_NO_ELEVATE = ("--agent", "--tg-engine", "--tg-agent", "--tg-pad", "--tg-idle", "--tg-gui", "--move-data", "--primeinput", "--sunlaunch", "--typepin")
def elevate_now():
    """Restart this program with the UAC 'run as administrator' prompt. -> True if Windows started it."""
    exe = sys.executable
    if getattr(sys, "frozen", False): params = subprocess.list2cmdline(sys.argv[1:])
    else:
        pw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.basename(exe).lower() == "python.exe" and os.path.exists(pw): exe = pw        # no console window
        params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, os.getcwd(), 1) > 32
if os.name == "nt" and __name__ == "__main__" and not is_admin() and not any(f in sys.argv for f in _NO_ELEVATE):
    if not elevate_now(): ctypes.windll.user32.MessageBoxW(None, "WoL Host needs administrator rights to set up this PC.\nOpen it again and choose Yes in the Windows prompt.", "WoL Host", 0x10)
    sys.exit(0)
def tsexe():
    w = r"C:\Program Files\Tailscale\tailscale.exe"
    return w if os.path.exists(w) else (shutil.which("tailscale") or "tailscale")
def ts_ip():
    rc, out = sh(f'"{tsexe()}" ip -4', 20)
    return out.split()[0] if rc == 0 and out.startswith("100.") else ""
def ts_unattended(force=False):
    """Is Tailscale in 'unattended' mode (it keeps running before anybody signs in)? True / False, None when it cannot be read. Cached for a minute."""
    if not force and "tu" in _cache and time.time() - _cache["tu"][0] < 60: return _cache["tu"][1]
    rc, out = sh(f'"{tsexe()}" debug prefs', 20); v = None
    try: v = bool(json.loads(out[out.index("{"):]).get("ForceDaemon"))
    except Exception: pass
    _cache["tu"] = (time.time(), v); return v
def ensure_unattended():
    """Tailscale only stays connected at the Windows sign-in screen (before anyone logs in) when it runs in 'unattended' mode. Without it the PC shows
    Offline in WoL Remote after a wake until somebody signs in on the PC. Makes the Tailscale service start by itself at boot and restart if it stops,
    switches unattended mode on (it is only a setting: safe to repeat), and checks that Windows really took it. -> True when it is on."""
    sh("sc config Tailscale start= auto", 20)
    sh("sc failure Tailscale reset= 86400 actions= restart/5000/restart/5000/restart/5000", 20)
    rc, out = sh(f'"{tsexe()}" set --unattended', 30); log(f"tailscale set --unattended: rc={rc} {out[:120]}")
    st = ts_unattended(True)
    if st is not True:                                                  # an older Tailscale has no 'set --unattended': 'up' does the same
        rc, out = sh(f'"{tsexe()}" up --unattended --reset', 60); log(f"tailscale up --unattended --reset: rc={rc} {out[:120]}")
        st = ts_unattended(True)
    log(f"tailscale unattended mode (runs before sign-in): {st}")
    return st is True
def macs():
    seen = []
    for m in re.findall(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", sh("getmac /fo csv /nh")[1]):
        v = m.lower().replace("-", ":")
        if v not in seen and v != "00:00:00:00:00:00": seen.append(v)
    return seen
_cache = {}
def physical_macs(force=False):
    """MACs of real network adapters (the ones that can receive a magic packet). Cached: PowerShell is slow."""
    if not force and "wm" in _cache and time.time() - _cache["wm"][0] < 600: return _cache["wm"][1]
    out, seen = ps("Get-NetAdapter -Physical | ForEach-Object { $_.MacAddress }")[1], []
    for m in re.findall(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", out):
        v = m.lower().replace("-", ":")
        if v not in seen: seen.append(v)
    _cache["wm"] = (time.time(), seen or macs()); return _cache["wm"][1]
def users(force=False):
    """Enabled local Windows accounts that can sign in (cached: PowerShell is slow)."""
    if not force and "u" in _cache and time.time() - _cache["u"][0] < 20: return _cache["u"][1]
    out = ps("Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin 'Guest','DefaultAccount','WDAGUtilityAccount' } | ForEach-Object { $_.Name + '|' + $_.PrincipalSource }")[1]
    names, msa = [], []
    for l in out.splitlines():
        if "|" not in l or l.lower().startswith(("get-", "at line")): continue
        n, src = l.rsplit("|", 1); n = n.strip()
        if n: names.append(n)
        if n and src.strip().lower() == "microsoftaccount": msa.append(n.lower())      # signs in with the Windows Hello PIN, not a password we could use
    _cache["u"] = (time.time(), names); _cache["m"] = (time.time(), msa); return names
def lan_ips():
    try: return [i for i in socket.gethostbyname_ex(socket.gethostname())[2] if not i.startswith(("127.", "100."))]
    except Exception: return []
def macs_cached(force=False):
    """macs() runs getmac.exe, lan_ips() a name lookup: both can take many seconds while Windows is still starting, longer than the PC app waits for an answer (then the PC
    showed Offline at the sign-in screen). So the agent's reply uses these cached copies and the refresher keeps them fresh."""
    if force or "mm" not in _cache or time.time() - _cache["mm"][0] > 120: _cache["mm"] = (time.time(), macs())
    return _cache["mm"][1]
def lan_ips_cached(force=False):
    if force or "li" not in _cache or time.time() - _cache["li"][0] > 120: _cache["li"] = (time.time(), lan_ips())
    return _cache["li"][1]

# ---------------- host agent (answers the client's "who are you?" over Tailscale) ----------------
# NOTE: the agent uses the standard library only, so it also runs as SYSTEM without customtkinter installed.
APPDIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "WoLHost")
LOG = os.path.join(APPDIR, "agent.log")
def log(msg):
    try:
        os.makedirs(APPDIR, exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as f: f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg) + "\n")
    except Exception: pass
def agent_up():
    try: socket.create_connection(("127.0.0.1", HPORT), 2).close(); return True
    except Exception: return False
def disk_free_mb():
    """Smallest free space (MB) on the drives the agent's data and Sunshine's config really live on (follows the D: junctions). A full disk silently loses pairings."""
    vals = []
    for p in (APPDIR, os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Sunshine", "config")):
        try: vals.append(shutil.disk_usage(p).free)
        except Exception: pass
    return min(vals) // 2**20 if vals else -1
def log_tail(n=3):
    try: return " | ".join(open(LOG, encoding="utf-8").read().strip().splitlines()[-n:])
    except Exception: return "no log yet"

# ---------------- Windows sessions + remote sign-in / sign-out ----------------
# The client app sends commands as one JSON line; every command that touches accounts needs the access key (shown in WoL Host > This PC).
# Sign-in works through Windows' own auto-logon: the password goes into an LSA secret (never a plain registry value), the PC restarts,
# Windows signs the user in, and the agent wipes the auto-logon settings again as soon as the session exists.
KEYF, PENDING = os.path.join(APPDIR, "agent.key"), os.path.join(APPDIR, "pending_login.json")
WL = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_login_lock, _fail = threading.Lock(), []
def agent_key():
    try: k = open(KEYF, encoding="utf-8").read().strip()
    except Exception: k = ""
    if len(k) < 16:
        k = secrets.token_hex(12); os.makedirs(APPDIR, exist_ok=True)
        with open(KEYF, "w", encoding="utf-8") as f: f.write(k)
        sh(f'icacls "{KEYF}" /inheritance:r /grant:r SYSTEM:F Administrators:F', 20)
    return k
LOCK_S = 30                                                              # cooldown after too many wrong PINs / passwords: 30 s
def lock_left(fails, window):
    """Seconds of cooldown left (0 = not locked). 5 wrong tries inside `window` s lock for LOCK_S s counted from the last wrong try; then the counter starts again."""
    now = time.time(); fails[:] = [t for t in fails if now - t < window]
    if len(fails) >= 5:
        left = fails[-1] + LOCK_S - now
        if left > 0: return left
        fails.clear()
    return 0
def locked_out(): return lock_left(_fail, 60) > 0
def lock_resp():
    n = max(1, int(math.ceil(lock_left(_fail, 60)))); return {"ok": False, "msg": f"Too many wrong attempts - try again in {n}s", "wait": n}
def key_ok(k):
    import hmac
    if locked_out(): return False
    if hmac.compare_digest(str(k), agent_key()): return True
    _fail.append(time.time()); return False
def sessions():
    """Windows sessions that have a user in them (signed in, locked or disconnected). Not localized, no PowerShell."""
    class INFO(ctypes.Structure): _fields_ = [("SessionId", ctypes.c_ulong), ("Station", ctypes.c_wchar_p), ("State", ctypes.c_int)]
    wts, out, p, n = ctypes.windll.wtsapi32, [], ctypes.c_void_p(), ctypes.c_ulong()
    if not wts.WTSEnumerateSessionsW(0, 0, 1, ctypes.byref(p), ctypes.byref(n)): return out
    raw = []
    try:
        arr = ctypes.cast(p, ctypes.POINTER(INFO))
        for i in range(n.value):
            si = arr[i]
            if si.State not in (0, 1, 4): continue                      # active / connected / disconnected
            buf, ln = ctypes.c_void_p(), ctypes.c_ulong()
            if wts.WTSQuerySessionInformationW(0, si.SessionId, 5, ctypes.byref(buf), ctypes.byref(ln)):
                name = ctypes.wstring_at(buf.value) if buf.value else ""; wts.WTSFreeMemory(buf)
                raw.append(f"{si.SessionId}:{si.Station}:state{si.State}:{name!r}")
                low = name.lower()
                if not name or si.SessionId == 0 or name.endswith("$") or low in ("system", "local service", "network service") or low.startswith(("dwm-", "umfd-")):
                    continue                                            # the sign-in screen / services / Windows' own virtual accounts are not a person who is signed in
                out.append({"id": si.SessionId, "user": name, "state": "disconnected" if si.State == 4 else "active"})
    finally: wts.WTSFreeMemory(p)
    sig = "|".join(raw)
    if sig != _sess_log[0]:                                             # log every change once, so a wrong "signed in" can be traced from the agent log
        _sess_log[0] = sig; log(f"sessions seen by Windows: {sig or '(none)'} -> counted as signed in: {[s['user'] for s in out] or 'nobody'}")
    return out
_sess_log = [None]
def has_session():
    try: return bool(sessions())
    except Exception: return False
def logon_check(user, pw):
    """Check a Windows password with LogonUser. -> (ok, windows_error_code). One attempt (a second one on 1385 only): every wrong try counts toward a Windows lockout."""
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.LogonUserW.restype = wintypes.BOOL
    dom, name = (None, user) if "@" in user else (user.split("\\", 1) if "\\" in user else (".", user))
    first = 0
    for typ in (2, 3):                                                  # interactive; then network only if interactive sign-in is not granted to the account
        tok = wintypes.HANDLE()
        if adv.LogonUserW(name, dom, pw, typ, 0, ctypes.byref(tok)):
            ctypes.windll.kernel32.CloseHandle(tok); return True, 0
        e = ctypes.get_last_error(); first = first or e
        if e != 1385: break
    log(f"logon check for {user} failed with Windows error {first}")
    return False, first
LOGON_MSG = {1326: "Windows says the username or password is wrong (error 1326). For a Microsoft account use its PIN",
             1327: "Windows refuses this account (error 1327): a blank password cannot be used remotely - set a remote PIN in WoL Host > Remote PIN",
             1331: "The account is disabled (error 1331)", 1909: "The account is locked out (error 1909)", 1330: "The password has expired (error 1330)",
             1385: "The account is not allowed to sign in interactively (error 1385)", 1355: "Windows could not find that account (error 1355)"}
def verify_logon(user, pw):
    ok, e = logon_check(user, pw)
    return (True, "Password is correct") if ok else (False, LOGON_MSG.get(e, f"Windows rejected the logon (error {e})"))
def lsa_secret(name, value):
    """Write (or, with value=None, delete) an LSA secret. -> Windows error code, 0 = ok"""
    class US(ctypes.Structure): _fields_ = [("Length", ctypes.c_ushort), ("Max", ctypes.c_ushort), ("Buffer", ctypes.c_wchar_p)]
    class OA(ctypes.Structure): _fields_ = [("Length", ctypes.c_ulong), ("Root", ctypes.c_void_p), ("Name", ctypes.c_void_p), ("Attr", ctypes.c_ulong), ("SD", ctypes.c_void_p), ("QOS", ctypes.c_void_p)]
    def us(t): return US(len(t) * 2, len(t) * 2 + 2, t)
    adv = ctypes.windll.advapi32; h = ctypes.c_void_p(); oa = OA(); oa.Length = ctypes.sizeof(oa)
    st = adv.LsaOpenPolicy(None, ctypes.byref(oa), 0x20, ctypes.byref(h))          # POLICY_CREATE_SECRET
    if st: return adv.LsaNtStatusToWinError(st)
    try:
        st = adv.LsaStorePrivateData(h, ctypes.byref(us(name)), None if value is None else ctypes.byref(us(value)))
        return adv.LsaNtStatusToWinError(st) if st else 0
    finally: adv.LsaClose(h)
def set_autologon(user, pw):
    import winreg as w
    with w.OpenKey(w.HKEY_LOCAL_MACHINE, WL, 0, w.KEY_SET_VALUE | w.KEY_WOW64_64KEY) as k:
        for n, v in (("AutoAdminLogon", "1"), ("DefaultUserName", user), ("DefaultDomainName", socket.gethostname())): w.SetValueEx(k, n, 0, w.REG_SZ, v)
        w.SetValueEx(k, "AutoLogonCount", 0, w.REG_DWORD, 1)
        try: w.DeleteValue(k, "DefaultPassword")                       # never leave a plain-text password in the registry
        except OSError: pass
    err = lsa_secret("DefaultPassword", pw)
    if err: raise RuntimeError(f"could not store the password securely (Windows error {err})")
    try:                                                                # "Windows Hello only" mode makes Windows ignore auto-logon
        with w.CreateKeyEx(w.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device", 0, w.KEY_SET_VALUE | w.KEY_QUERY_VALUE | w.KEY_WOW64_64KEY) as pk:
            try: cur = w.QueryValueEx(pk, "DevicePasswordLessBuildVersion")[0]
            except OSError: cur = 0
            if cur != 0: w.SetValueEx(pk, "DevicePasswordLessBuildVersion", 0, w.REG_DWORD, 0); log("turned off Windows-Hello-only sign-in so auto-logon works")
    except Exception as e: log(f"passwordless setting: {e!r}")
def clear_autologon():
    import winreg as w
    try:
        with w.OpenKey(w.HKEY_LOCAL_MACHINE, WL, 0, w.KEY_SET_VALUE | w.KEY_WOW64_64KEY) as k:
            w.SetValueEx(k, "AutoAdminLogon", 0, w.REG_SZ, "0")
            for n in ("DefaultPassword", "AutoLogonCount"):
                try: w.DeleteValue(k, n)
                except OSError: pass
    except Exception as e: log(f"clear autologon: {e!r}")
    lsa_secret("DefaultPassword", None)
_stale_checked = [0.0]
def stale_autologon():
    """Windows auto-logon left switched on (by an older version or an interrupted sign-in) would sign an account in at every boot. With no sign-in pending, turn it off."""
    if time.time() - _stale_checked[0] < 30: return
    _stale_checked[0] = time.time()
    try:
        import winreg as w
        with w.OpenKey(w.HKEY_LOCAL_MACHINE, WL, 0, w.KEY_QUERY_VALUE | w.KEY_WOW64_64KEY) as k:
            try: on = str(w.QueryValueEx(k, "AutoAdminLogon")[0]) == "1"
            except OSError: on = False
            try: pw = bool(w.QueryValueEx(k, "DefaultPassword")[0])
            except OSError: pw = False
            try: who = str(w.QueryValueEx(k, "DefaultUserName")[0])
            except OSError: who = "?"
        if on or pw: clear_autologon(); log(f"auto-logon was switched on for '{who}' - turned it off (Windows no longer signs anyone in by itself at start-up). Something set it: netplwiz, an auto-logon tool, or an old WoL Host")
    except Exception as e: log(f"stale autologon check: {e!r}")
def remove_agent_service():
    """Turns the WoL Host agent service off: stops it, deletes its start-at-boot task and closes its firewall port. UPDATE (or Set up) installs it again."""
    sh("schtasks /end /tn WoLHostAgent", 20); time.sleep(1)
    sh("schtasks /delete /tn WoLHostAgent /f", 20)
    ps("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '\\s--agent(\\s|\"|$)' -and $_.CommandLine -match 'wol_host|WoL-Host' -and $_.ProcessId -ne " + str(os.getpid()) + " } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    sh('netsh advfirewall firewall delete rule name="WoL Host Agent"', 20)
    for _ in range(10):                                                   # give it a few seconds to disappear
        if not agent_up(): break
        time.sleep(0.5)
    still_task = sh("schtasks /query /tn WoLHostAgent", 20)[0] == 0
    if agent_up() or still_task: return False, "WoL Host agent service could not be fully stopped" + (" (its task still exists)" if still_task else " (it is still answering)")
    return True, "WoL Host agent service turned off"
def remove_all_services():
    """\"Remove service\": TimeGuard service + WoL Host agent service. Returns (ok, text)."""
    ok1, m1 = tg_remove(); ok2, m2 = remove_agent_service()
    return (ok1 and ok2), (m1 + " · " + m2)
def tg_remove():
    """Removes the TimeGuard background service and its widgets. Returns (ok, text)."""
    try:
        tgm = load_timeguard()
        probs = tgm.uninstall_protection()
        return (not probs), ("TimeGuard service removed" if not probs else "TimeGuard service: " + str(probs)[:300])
    except Exception as e:
        log(f"timeguard remove: {e!r}"); return False, f"TimeGuard service could not be removed ({e})"
def tg_repair():
    """Same as pressing "Install / repair protection" in the TimeGuard tab. Returns (ok, text)."""
    try:
        tgm = load_timeguard()
        probs = tgm.install_protection()
        return (not probs), ("TimeGuard protection repaired" if not probs else "TimeGuard protection: " + "; ".join(str(p) for p in probs)[:300])
    except Exception as e:
        log(f"timeguard repair: {e!r}"); return False, f"TimeGuard protection could not be repaired ({e})"
def pending_tick():
    """After a remote sign-in: wipe the auto-logon password as soon as that user is signed in (or after 10 minutes)."""
    try: d = json.load(open(PENDING, encoding="utf-8"))
    except Exception: stale_autologon(); return                         # no remote sign-in in progress: nothing may sign anyone in at boot
    if any(s["user"].lower() == d.get("user", "").lower() for s in sessions()) or time.time() - d.get("ts", 0) > 600:
        clear_autologon()
        try: os.remove(PENDING)
        except OSError: pass
        log("remote sign-in finished - auto-logon password wiped")
def do_login(user, pw):
    return do_login_typed(user, pw, "password")                         # rpc() already pre-checked the password; Windows' own sign-in screen is the final judge
_last_logoff = [0.0]
def do_logoff(user):
    ids = [s["id"] for s in sessions() if s["user"].lower() == user.lower()]
    if not ids: return False, f"{user} is not signed in"
    for i in ids: ctypes.windll.wtsapi32.WTSLogoffSession(0, i, False)
    _last_logoff[0] = time.time()
    return True, f"Signing {user} out"
# ---------------- Microsoft accounts: sign in / out with the Windows Hello PIN instead of the online password ----------------
# Windows cannot check a PIN from outside (it is bound to this PC), so:
#  * sign-in: the PIN is typed into Windows' own sign-in screen and WINDOWS decides whether it is right. No restart, no auto-logon password.
#  * once Windows has let the user in with that PIN, a salted PBKDF2 hash of it is kept (SYSTEM/Administrators-only file); that hash authorises sign-outs.
PROOF, PENDPIN = os.path.join(APPDIR, "pin_proof.json"), os.path.join(APPDIR, "pending_pin.json")
LOGINFAIL = os.path.join(APPDIR, "login_fail.json")          # written when Windows did not accept a PIN / password typed at the sign-in screen
def login_fail():
    try: d = json.load(open(LOGINFAIL, encoding="utf-8")); return d if isinstance(d, dict) else None
    except Exception: return None
def is_msa(user):
    users(); return user.lower() in _cache.get("m", (0, []))[1]
def _write_private(path, text):
    open(path, "w").close(); sh(f'icacls "{path}" /inheritance:r /grant:r SYSTEM:F Administrators:F', 20)      # lock the file down BEFORE the secret goes in
    with open(path, "w", encoding="utf-8") as f: f.write(text)
def _pbkdf(pin, salt): import hashlib; return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 200000).hex()
def _proof_load():
    try: return json.load(open(PROOF, encoding="utf-8"))
    except Exception: return {}
def pin_matches(user, pin):
    """True / False against the PIN Windows last accepted for this user, None if no PIN is on record yet."""
    import hmac
    e = _proof_load().get(user.lower())
    if not e: return None
    return hmac.compare_digest(_pbkdf(pin, bytes.fromhex(e["salt"])), e["hash"])
def pin_tick():
    """After a remote PIN sign-in: once the user really has a session, Windows accepted the PIN -> remember its hash."""
    try: d = json.load(open(PENDPIN, encoding="utf-8"))
    except Exception: return
    if any(s["user"].lower() == d.get("user", "").lower() for s in sessions()):
        pr = _proof_load(); pr[d["user"].lower()] = {"salt": d["salt"], "hash": d["hash"]}; _write_private(PROOF, json.dumps(pr)); log(f"Windows accepted the PIN for {d['user']}")
    elif time.time() - d.get("ts", 0) < 180: return
    try: os.remove(PENDPIN)
    except OSError: pass
# ---------------- Remote PIN (set in the Remote PIN tab) ----------------
# For accounts whose Windows password has been REMOVED: a PIN chosen here in WoL Host (not the Windows password, not the Windows Hello PIN) is the only
# thing that authorises a remote sign-in / sign-out. Only a salted PBKDF2 hash is stored (SYSTEM / Administrators-only file).
HOSTPIN = os.path.join(APPDIR, "host_pins.json")
def hostpin_load():
    """{user: {salt, hash, mode?, exp?}}. A PIN with an expiry (exp = epoch seconds) is simply gone once its time is up (it is dropped from the file by the next set / clear)."""
    try: d = json.load(open(HOSTPIN, encoding="utf-8")); d = d if isinstance(d, dict) else {}
    except Exception: return {}
    now = time.time()
    return {k: v for k, v in d.items() if isinstance(v, dict) and not (int(v.get("exp") or 0) and now >= int(v["exp"]))}
def hostpin_users(): return sorted(hostpin_load())
def has_hostpin(user): return user.lower() in hostpin_load()
# Two kinds of remote PIN:  "blank" = the account has NO Windows password, the PIN alone signs it in and out (the original behaviour).
#                           "dual"  = the account keeps its Windows / Microsoft password (admins, Microsoft accounts, ...): the PIN alone signs it OUT,
#                                     signing it IN needs the PIN AND the password (Windows checks the password at its own sign-in screen).
def hostpin_mode(user): return "dual" if (hostpin_load().get(user.lower()) or {}).get("mode") == "dual" else "blank"
def hostpin_dual_users(): return sorted(k for k, v in hostpin_load().items() if isinstance(v, dict) and v.get("mode") == "dual")
def hostpin_valid(pin): return bool(re.fullmatch(r"\d{4,32}", pin or ""))
def hostpin_set(user, pin, mode="blank", seconds=0):
    """seconds = 0 -> the PIN never expires."""
    if not hostpin_valid(pin): raise ValueError("A PIN is 4 to 32 digits (numbers only).")
    os.makedirs(APPDIR, exist_ok=True)
    salt = secrets.token_bytes(16); d = hostpin_load()
    d[user.lower()] = {"salt": salt.hex(), "hash": _pbkdf(pin, salt), **({"mode": "dual"} if mode == "dual" else {}), **({"exp": int(time.time()) + int(seconds)} if seconds else {})}
    _write_private(HOSTPIN, json.dumps(d))
def hostpin_clear(user):
    d = hostpin_load(); d.pop(user.lower(), None); _write_private(HOSTPIN, json.dumps(d))
def hostpin_ok(user, pin):
    import hmac
    e = hostpin_load().get(user.lower())
    return bool(e) and hmac.compare_digest(_pbkdf(pin, bytes.fromhex(e["salt"])), e["hash"])
# ---------------- Access PIN = the remote PIN of each account (Remote PIN tab) ----------------
# There is no separate access PIN any more: the PIN set for a Windows account is ALSO what waking and streaming ask for. Every account has its own PIN
# (with its own optional expiry); the PIN of any account opens wake / stream. While no account has a PIN, nothing is asked for. The salted hashes of all
# the account PINs are pushed to the WoL Relay phone, which then asks for one of them before it sends a wake packet or lists the MAC addresses it finds.
ACCESSSYNC = os.path.join(APPDIR, "access_sync.json")        # result of the last push to the phone
RELAYSEC = os.path.join(APPDIR, "relay_secret.json")         # the phone token's secret (saved by Set up): lets this PC (and only it) set the PINs on the phone
def accesspin_active():
    """The remote PINs that are valid right now: {user: {salt, hash, exp?}}. Empty = no account has a PIN, so wake / stream ask for none."""
    return {k: v for k, v in hostpin_load().items() if v.get("hash") and v.get("salt")}
def accesspin_who(pin):
    """The account whose PIN this is (lower case), or None."""
    import hmac
    if not hostpin_valid(pin): return None
    for u, e in accesspin_active().items():
        try:
            if hmac.compare_digest(_pbkdf(pin, bytes.fromhex(e["salt"])), e["hash"]): return u
        except Exception: pass
    return None
def accesspin_ok(pin): return accesspin_who(pin) is not None
_afail = []
ACCESS_MSG = {"NEED_PIN": "A PIN is required (it is the PIN set for an account in WoL Host > Remote PIN).", "BAD_PIN": "That PIN is wrong.", "LOCKED": "Too many wrong PINs - try again in 30s."}
def access_wait(): return max(1, int(math.ceil(lock_left(_afail, 300))))
def access_msg(code): return f"Too many wrong PINs - try again in {access_wait()}s" if code == "LOCKED" else ACCESS_MSG[code]
def access_check(pin):
    """None = allowed (no PIN set, or the right one). Otherwise 'NEED_PIN' / 'BAD_PIN' / 'LOCKED'."""
    if not accesspin_active(): return None
    now = time.time()
    if lock_left(_afail, 300) > 0: return "LOCKED"
    if not pin: return "NEED_PIN"
    if accesspin_ok(pin): return None
    _afail.append(now); log("wrong PIN (wake / stream access)"); return "BAD_PIN"
def phone_secret():
    try:
        with open(RELAYSEC, encoding="utf-8") as f: return str((json.load(f) or {}).get("secret") or "")
    except Exception: return ""
def phone_request(action, data="", timeout=8):
    """One signed request to the WoL Relay phone (role: host). -> its one-line reply."""
    import hmac, hashlib
    ip, sec = relay_ip(), phone_secret()
    if not ip or not sec: raise RuntimeError("phone not linked")
    t = str(int(time.time())); msg = f"{t}|||{action}" + (f"|{data}" if data else "")
    sig = hmac.new(sec.encode(), msg.encode(), hashlib.sha256).hexdigest()
    body = {"ts": t, "mac": "", "ip": "", "action": action, "sig": sig, "name": socket.gethostname(), "role": "host"}
    if data: body["data"] = data
    with socket.create_connection((ip, 48999), timeout=timeout) as s:
        s.settimeout(timeout); s.sendall((json.dumps(body) + "\n").encode()); return s.makefile().readline().strip()
HOSTSENT = os.path.join(APPDIR, "host_sent.json")              # what the phone last confirmed: {"sig": ..., "t": ...}
def host_report():
    """-> (this PC's Tailscale IP, its physical MAC addresses): what the phone and (through it) the WoL Remote PCs need to wake and reach this PC."""
    return ts_ip(), [m for m in physical_macs() if m and m != "00:00:00:00:00:00"] or macs_cached()
def host_sig(tip, macs): return hashlib.sha256((tip + "|" + ",".join(sorted(macs))).encode()).hexdigest()[:16]
def send_host_macs(tries=5):
    """Tell the WoL Relay phone this PC's Tailscale IP and PHYSICAL MAC address(es). Sent right after joining with a token, and again by host_register_loop() whenever the
    phone has not confirmed it yet or the IP / MACs changed. The phone saves them under Hosts (its owner can remove them there) and forwards them to every WoL Remote PC
    linked with a token. The request is signed with the token secret and carries role "host" like the PIN sync. -> (ok, message)"""
    macs = [m for m in physical_macs(True) if m and m != "00:00:00:00:00:00"] or macs_cached(True)
    if not macs: return False, "no network adapter with a MAC address was found"
    last = ""
    for i in range(tries):
        try:
            tip = ts_ip()                                                          # this PC's Tailscale address goes first, then the MACs: "100.x.y.z,aa:bb:..,cc:dd:.."
            r = phone_request("sethost", ",".join(([tip] if tip else []) + macs))
            if r == "OK":
                try: _write_private(HOSTSENT, json.dumps({"sig": host_sig(tip or "", macs), "t": time.time()}))
                except Exception as e: log(f"host_sent state: {e!r}")
                log(f"sent Tailscale IP {tip or '?'} and MAC address(es) to the phone: {macs}"); return True, f"{tip or 'no Tailscale IP'} · MAC " + ", ".join(macs)
            last = r or "no answer"
            if "DENIED" in last or "ERROR" in last: break                      # a real refusal will not change by waiting
        except Exception as e: last = str(e)
        time.sleep(2)
    log(f"could not send the MAC address to the phone: {last}")
    return False, last + (" (update the WoL Relay app on the phone)" if "unknown action" in last.lower() or "bad PIN data" in last else "")
def host_register_loop():
    """Agent thread: keeps the phone's Hosts entry for this PC up to date. Sends when the phone never confirmed this PC's current Tailscale IP + MACs (the phone was off when
    the token was used, or this PC was set up by an older version) or when they changed. Once confirmed it stays quiet, so a host the phone's owner removed is not re-added."""
    while True:
        try:
            if relay_ip() and phone_secret():
                tip, macs = host_report()
                if tip and macs:
                    try: sent = json.load(open(HOSTSENT, encoding="utf-8")).get("sig")
                    except Exception: sent = None
                    if sent != host_sig(tip, macs): send_host_macs(tries=1)
        except Exception as e: log(f"host register: {e!r}")
        time.sleep(30)
def sync_state():
    try: d = json.load(open(ACCESSSYNC, encoding="utf-8")); return d if isinstance(d, dict) else {}
    except Exception: return {}
def phone_pin_state():
    """What the phone must hold: "clear" (no account has a PIN) or "all:<user hex>:<salt>:<hash>:<exp>;..." - one entry per account (user name hex-encoded so no
    character of it can clash with the separators)."""
    ents = accesspin_active()
    if not ents: return "clear"
    return "all:" + ";".join(f"{u.encode('utf-8').hex()}:{e['salt']}:{e['hash']}:{int(e.get('exp') or 0)}" for u, e in sorted(ents.items()))
def access_sync(force=False):
    """Push the account PINs (or their removal) to the phone the PC was set up with. Cheap when nothing changed. -> (ok, message)"""
    import hashlib
    state = phone_pin_state()
    sig = hashlib.sha256(state.encode()).hexdigest()[:16]; st = sync_state(); now = time.time()
    if not force and st.get("sig") == sig and now - float(st.get("t") or 0) < (600 if st.get("ok") else 60): return bool(st.get("ok")), str(st.get("msg") or "")
    if not relay_ip() or not phone_secret():
        res = (True, "") if state == "clear" else (False, "This PC is not linked to the phone yet, so the phone cannot ask for these PINs. Run Set up and paste the phone token.")
    else:
        try:
            r = phone_request("setpin", state)
            res = (True, "The phone has the PINs.") if r == "OK" else (False, "The phone said: " + (r or "nothing") + (" (update the WoL Relay app on the phone)" if "bad PIN data" in (r or "") else ""))
            if r == "OK" and state == "clear": res = (True, "")
        except Exception as e: res = (False, f"The phone did not answer ({e}). It is tried again every minute.")
    try: _write_private(ACCESSSYNC, json.dumps({"sig": sig, "t": now, "ok": res[0], "msg": res[1]}))
    except Exception as e: log(f"access sync state: {e!r}")
    if not res[0]: log("PIN sync to the phone: " + res[1])
    return res
def access_sync_loop():
    """Agent thread: keeps the phone's copy of the account PINs equal to this PC's (a PIN that expires here changes the state, so the phone follows)."""
    while True:
        try: access_sync()
        except Exception as e: log(f"access sync: {e!r}")
        time.sleep(15)
def windows_pw_state(user):
    """'blank' (no Windows password - what the remote PIN needs), 'password' (it still has one) or 'unknown'. One LogonUser attempt."""
    ok, e = logon_check(user, "")
    return "blank" if ok or e == 1327 else "password" if e == 1326 else "unknown"
def helper_cmd(args):
    """Command line that runs THIS program again with other arguments (no copying: the agent is already running from a place SYSTEM can read)."""
    if getattr(sys, "frozen", False): return f'"{sys.executable}" {args}'
    py = sys.executable; pw = os.path.join(os.path.dirname(py), "pythonw.exe")
    if os.path.basename(py).lower() == "python.exe" and os.path.exists(pw): py = pw
    return f'"{py}" "{os.path.abspath(__file__)}" {args}'
def spawn_in_console_session(cmd, desktop=r"winsta0\winlogon", cwd=None):
    """Start a command as SYSTEM inside the logged-on console session, on the Windows sign-in desktop (the agent itself lives in session 0)."""
    from ctypes import wintypes
    k32, adv = ctypes.windll.kernel32, ctypes.windll.advapi32
    k32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD; k32.GetCurrentProcess.restype = wintypes.HANDLE
    sid = k32.WTSGetActiveConsoleSessionId()
    if sid == 0xFFFFFFFF: raise RuntimeError("the PC has no console session yet - is it fully started?")
    class SI(ctypes.Structure): _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR)] + [(n, wintypes.DWORD) for n in ("dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")] + [("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]
    class PI(ctypes.Structure): _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    adv.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(SI), ctypes.POINTER(PI)]
    tok, dup = wintypes.HANDLE(), wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x02000000, ctypes.byref(tok)): raise RuntimeError(f"OpenProcessToken failed ({ctypes.GetLastError()})")
    try:
        if not adv.DuplicateTokenEx(tok, 0x02000000, None, 2, 1, ctypes.byref(dup)): raise RuntimeError(f"DuplicateTokenEx failed ({ctypes.GetLastError()})")
        try:
            if not adv.SetTokenInformation(dup, 12, ctypes.byref(ctypes.c_ulong(sid)), 4): raise RuntimeError(f"SetTokenInformation failed ({ctypes.GetLastError()})")
            si = SI(); si.cb = ctypes.sizeof(si); si.lpDesktop = desktop; pi = PI(); buf = ctypes.create_unicode_buffer(cmd)
            if not adv.CreateProcessAsUserW(dup, None, buf, None, None, False, 0x08000000, None, cwd, ctypes.byref(si), ctypes.byref(pi)): raise RuntimeError(f"CreateProcessAsUser failed ({ctypes.GetLastError()})")
            k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)
        finally: k32.CloseHandle(dup)
    finally: k32.CloseHandle(tok)
def typepin_main(path, kind="pin", watch=False, user=""):
    """Helper process (`--typepin <file> [pin|password|blank] [watch]`, runs on the sign-in desktop): wake the lock screen, type the PIN / password (kind "blank": an account with no Windows password - nothing is typed), press Enter. ONE attempt only.
    With `watch` (a remote sign-in) it then waits for the user's session; if none appears Windows rejected the secret -> recorded in login_fail.json."""
    from ctypes import wintypes
    try: pin = open(path, encoding="utf-8").read()
    finally:
        try: os.remove(path)
        except OSError: pass
    class KI(ctypes.Structure): _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]
    class MI(ctypes.Structure): _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]
    class HI(ctypes.Structure): _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]
    class UN(ctypes.Union): _fields_ = [("mi", MI), ("ki", KI), ("hi", HI)]
    class IN(ctypes.Structure): _fields_ = [("type", wintypes.DWORD), ("u", UN)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True); k32.CreateMutexW.restype = ctypes.c_void_p; k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    _mx = k32.CreateMutexW(None, 0, "Global\\WoLHostTypePin")             # only ONE typing helper may exist at any time: a second one exits without typing a thing
    if _mx and ctypes.get_last_error() == 183: log("typepin: another typing helper is already running - this one types nothing"); return
    u32 = ctypes.windll.user32; u32.OpenInputDesktop.restype = wintypes.HANDLE; u32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
    try:
        d = u32.OpenInputDesktop(0, False, 0x10000000)
        if d: u32.SetThreadDesktop(d)                                    # follow whatever desktop Windows is showing (lock / sign-in screen)
    except Exception as e: log(f"typepin: desktop attach: {e!r}")
    sent = {"ok": 0, "blocked": 0}
    def key(vk=0, ch=None, up=False):
        scan = ord(ch) if ch else u32.MapVirtualKeyW(vk, 0)                # real scan code too: the sign-in screen ignores bare virtual keys
        i = IN(1, UN(ki=KI(0 if ch else vk, scan, (2 if up else 0) | (4 if ch else 0), 0, 0)))
        sent["ok" if u32.SendInput(1, ctypes.byref(i), ctypes.sizeof(i)) else "blocked"] += 1
    def tap(vk=0, ch=None): key(vk, ch); time.sleep(0.04); key(vk, ch, True); time.sleep(0.08)
    def typechar(c):
        r = u32.VkKeyScanW(ord(c)) if ord(c) < 0x10000 else -1
        if r == -1 or r & 0xF800: tap(ch=c); return                         # not on this keyboard layout: Unicode fallback
        vk, mods = r & 0xFF, (r >> 8) & 7
        held = [m for bit, m in ((1, 0x10), (2, 0x11), (4, 0x12)) if mods & bit]
        for m in held: key(m); time.sleep(0.03)
        tap(vk)
        for m in reversed(held): key(m, up=True); time.sleep(0.03)
    for _ in range(40):                                                  # right after a sign-out the screen can take a while to come back
        if logonui_sessions(): break
        time.sleep(0.5)
    else:
        log("typepin: the lock / sign-in screen is NOT showing - nothing typed")                  # never type a PIN into a normal desktop
        if watch:
            try: _write_private(LOGINFAIL, json.dumps({"ts": time.time(), "kind": kind, "why": "no_screen"}))
            except Exception as e: log(f"login_fail: {e!r}")
        return
    time.sleep(2.5)
    tap(0x10); time.sleep(1.0); tap(0x10); time.sleep(3.0)   # Shift twice: dismisses the lock screen and shows the PIN box, types nothing
    if u32.GetKeyState(0x14) & 1: tap(0x14); log("typepin: Caps Lock was on - turned it off (it would have flipped the case of every letter)")
    for c in pin:
        if kind == "pin" and c.isascii() and c.isdigit(): tap(vk=0x30 + int(c))      # a PIN's digits: the number row, whatever the layout
        else: typechar(c)                                                          # passwords: the key (and Shift) this keyboard layout needs for exactly this character
    time.sleep(0.4); tap(0x0D)
    log(f"typepin: typed {len(pin)} characters ({kind}) + Enter at the sign-in screen (key events accepted {sent['ok']}, blocked {sent['blocked']})")   # the secret itself is never logged
    if watch:
        t_enter = time.time()
        for i in range(45):
            time.sleep(1)
            if sessions(): log("typepin: Windows accepted it - the user is signed in"); return
            if user and i >= 3 and i % 2 == 1 and logon_rejected_since(t_enter, user):          # Windows logged a failed sign-in for this user: no need to wait out the full 45 s
                time.sleep(1.5)
                if sessions(): log("typepin: Windows accepted it - the user is signed in"); return
                try: _write_private(LOGINFAIL, json.dumps({"ts": time.time(), "kind": kind, "why": "rejected"}))
                except Exception as e: log(f"login_fail: {e!r}")
                log(f"typepin: Windows logged a failed sign-in for {user} {int(time.time() - t_enter)} s after Enter - the {kind} was rejected"); return
        try: _write_private(LOGINFAIL, json.dumps({"ts": time.time(), "kind": kind}))
        except Exception as e: log(f"login_fail: {e!r}")
        log(f"typepin: no session 45 s after Enter - Windows did not accept the {kind}")
def logon_rejected_since(t0, user):
    """True if Windows logged a failed sign-in (event 4625) for `user` after time t0. Best effort: it needs 'Audit logon failures' (on by default on Windows client
    editions). When nothing can be read this is False and the caller just waits for its normal timeout."""
    try:
        ms = int((time.time() - t0) * 1000) + 500
        rc, out = sh(f'wevtutil qe Security "/q:*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= {ms}]]]" /c:10 /rd:true /f:xml', 20)
        if rc != 0 or not out: return False
        u = user.strip().lower()
        for m in re.finditer(r"<Data Name=.TargetUserName.>([^<]*)</Data>", out):
            n = m.group(1).strip().lower()
            if n and (n == u or n in u or u in n): return True
    except Exception as e: log(f"failed-sign-in check: {e!r}")
    return False
LOGONUI_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
PROVIDER = {"password": "{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}", "pin": "{D6886603-9D2F-4EB2-B667-1971041FA96B}"}
def user_sid(user):
    rc, out = ps("(New-Object System.Security.Principal.NTAccount('%s','%s')).Translate([System.Security.Principal.SecurityIdentifier]).Value" % (socket.gethostname().replace("'", "''"), user.replace("'", "''")))
    last = out.strip().splitlines()[-1].strip() if out.strip() else ""
    return last if last.startswith("S-1-5-") else ""
def select_signin_tile(user, kind):
    """Make Windows' sign-in screen preselect this user and the password / PIN box (the same values Windows writes after every sign-in), then restart only
    the sign-in screen process (LogonUI.exe - Windows relaunches it at once, the PC does NOT restart) so it picks them up."""
    import winreg as w
    sid = user_sid(user)
    if not sid: log(f"tile select: could not find the SID of {user}"); return False
    with w.CreateKeyEx(w.HKEY_LOCAL_MACHINE, LOGONUI_KEY, 0, w.KEY_SET_VALUE | w.KEY_WOW64_64KEY) as k:
        for n, v in (("SelectedUserSID", sid), ("LastLoggedOnUserSID", sid), ("LastLoggedOnSAMUser", f"{socket.gethostname()}\\{user}"), ("LastLoggedOnProvider", PROVIDER.get(kind, PROVIDER["password"]))):
            w.SetValueEx(k, n, 0, w.REG_SZ, v)
    sh("taskkill /f /im LogonUI.exe", 20)
    for _ in range(30):
        time.sleep(0.5)
        if logonui_sessions(): log(f"tile select: sign-in screen reloaded for {user} ({kind})"); return True
    log("tile select: the sign-in screen did not come back in 15 s"); return False
def wait_signin_screen(timeout=30):
    """Right after a sign-out Windows needs a few seconds before its sign-in screen is back, and anything typed earlier goes nowhere.
    -> True once no user session is left and the screen has been up for 3 s in a row (False after `timeout`: the caller tries anyway)."""
    t0, since = time.time(), None
    while time.time() - t0 < timeout:
        if not sessions() and logonui_sessions():
            since = since or time.time()
            if time.time() - since >= 3: return True
        else: since = None
        time.sleep(0.5)
    log(f"sign-in screen: not ready after {timeout} s - trying anyway"); return False
_typing = {"ts": 0.0, "user": "", "hash": ""}           # when the agent last started typing a PIN / password at the sign-in screen
def do_login_typed(user, secret, kind):
    """Sign a user in WITHOUT restarting: type the password / PIN into Windows' own sign-in screen. Windows decides whether it is right."""
    known = [u.lower() for u in (_cache["u"][1] if "u" in _cache else users())]
    if user.lower() not in known: return False, "That Windows user does not exist (or is disabled) on this PC"
    if time.time() - _last_logoff[0] < 120:                              # someone was just signed out (switching users): Windows needs a moment to finish closing that session
        for _ in range(60):
            if not sessions(): break
            time.sleep(0.5)
        else: log("switch: the previous session was still closing after 30 s")
        time.sleep(1.5)
    ss = sessions()
    other = next((s["user"] for s in ss if s["user"].lower() != user.lower()), None)
    if other: return False, f"{other} is signed in - they must be signed out first"
    if ss: return False, f"{user} is already signed in"
    sh_ = hashlib.sha256((user.lower() + "\0" + secret).encode("utf-8")).hexdigest(); pend, fl = _typing, login_fail() or {}
    if pend["hash"] == sh_ and pend["ts"] and fl.get("ts", 0) > pend["ts"] and time.time() - pend["ts"] < 600:      # Windows already turned exactly this down: typing it again can only lock the account
        log(f"login for {user} refused: Windows already rejected this PIN / password")
        return False, f"Windows already rejected this {'PIN' if kind == 'pin' else 'password'} for {user}. It is NOT typed again - enter a different one."
    if pend["ts"] and time.time() - pend["ts"] < 60 and fl.get("ts", 0) <= pend["ts"]:               # the previous PIN is still being judged: typing again would only burn Windows' wrong-PIN attempts
        log(f"login for {user} refused: a sign-in was typed {int(time.time() - pend['ts'])} s ago and Windows has not answered yet")
        return False, f"A sign-in was typed {int(time.time() - pend['ts'])} s ago and Windows has not answered yet - wait for its result (it says if the PIN was wrong) before trying again."
    wait_signin_screen()
    try: select_signin_tile(user, kind)
    except Exception as e: log(f"tile select failed: {e!r}")                  # best effort: the default tile may already be the right one
    f = os.path.join(APPDIR, f"pin_{secrets.token_hex(4)}.tmp"); _write_private(f, secret)
    if kind == "pin":
        salt = secrets.token_bytes(16)
        _write_private(PENDPIN, json.dumps({"user": user, "salt": salt.hex(), "hash": _pbkdf(secret, salt), "ts": time.time()}))
    _typing.update(ts=time.time(), user=user, hash=sh_)
    try: spawn_in_console_session(helper_cmd(f'--typepin "{f}" {kind} watch "{user}"'))
    except Exception as e:
        _typing["ts"] = 0.0
        for x in (f, PENDPIN):
            try: os.remove(x)
            except OSError: pass
        return False, f"Could not reach the sign-in screen: {e}"
    if kind == "blank": return True, f"Signing {user} in at the Windows sign-in screen"
    return True, f"Typing the {'PIN' if kind == 'pin' else 'password'} at the Windows sign-in screen for {user}"
def do_login_pin(user, pin): return do_login_typed(user, pin, "pin")
def logonui_sessions():
    """Session ids that currently show the Windows lock / sign-in screen (LogonUI.exe) - for the log only."""
    out = sh('tasklist /fi "imagename eq LogonUI.exe" /fo csv /nh', 20)[1]; ids = []
    for l in out.splitlines():
        c = [x.strip('"') for x in l.split('","')]
        if len(c) >= 4 and c[0].lower().startswith("logonui") and c[3].isdigit(): ids.append(int(c[3]))
    return ids
def is_locked(): return bool(logonui_sessions())        # only one user can be signed in at a time, so any lock screen is theirs
# ---------------- wake the input of a freshly signed-in session ----------------
# After a REMOTE sign-in nothing has ever touched a mouse or keyboard inside the new session, and Windows then behaves as if no input exists yet:
# the pointer is not drawn, injected (Sunshine) key presses go nowhere, and the session's "last input" stays empty (so TimeGuard has no countdown).
# One physical key press fixes all of it - so the agent does exactly that, as SYSTEM inside the session: a 1-pixel mouse nudge, one Shift tap, a display wake,
# and a reload of the cursor set. It is repeated a few times (the shell and Sunshine start a little later) and whenever the client asks ("prime").
def shell_up():
    """True once explorer.exe runs in the console session = the user's desktop has been built."""
    try:
        k32 = ctypes.windll.kernel32; k32.WTSGetActiveConsoleSessionId.restype = ctypes.c_ulong; cons = k32.WTSGetActiveConsoleSessionId()
        for l in sh('tasklist /fi "imagename eq explorer.exe" /fo csv /nh', 20)[1].splitlines():
            c = [x.strip('"') for x in l.split('","')]
            if len(c) >= 4 and c[0].lower() == "explorer.exe" and c[3].isdigit() and int(c[3]) == cons: return True
    except Exception as e: log(f"shell check: {e!r}")
    return False
def primeinput_main():
    """Helper (`--primeinput`, runs as SYSTEM on the signed-in user's desktop): make Windows register input in this session. Nothing here can type text."""
    from ctypes import wintypes
    u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
    class KI(ctypes.Structure): _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]
    class MI(ctypes.Structure): _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]
    class HI(ctypes.Structure): _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]
    class UN(ctypes.Union): _fields_ = [("mi", MI), ("ki", KI), ("hi", HI)]
    class IN(ctypes.Structure): _fields_ = [("type", wintypes.DWORD), ("u", UN)]
    class CI(ctypes.Structure): _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD), ("hCursor", wintypes.HANDLE), ("x", wintypes.LONG), ("y", wintypes.LONG)]
    class LII(ctypes.Structure): _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]
    u32.OpenInputDesktop.restype = wintypes.HANDLE; u32.SetThreadDesktop.argtypes = [wintypes.HANDLE]; k32.GetTickCount.restype = wintypes.DWORD
    u32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, wintypes.UINT]
    u32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM, wintypes.UINT, wintypes.UINT, ctypes.c_void_p]
    try:
        d = u32.OpenInputDesktop(0, False, 0x10000000)
        if d: u32.SetThreadDesktop(d)
    except Exception as e: log(f"prime: desktop attach: {e!r}")
    def state():
        ci = CI(); ci.cbSize = ctypes.sizeof(ci); u32.GetCursorInfo(ctypes.byref(ci))
        li = LII(); li.cbSize = ctypes.sizeof(li); ok = u32.GetLastInputInfo(ctypes.byref(li))
        return ci.flags, (((k32.GetTickCount() - li.dwTime) & 0xFFFFFFFF) / 1000.0 if ok and li.dwTime else -1.0)
    def send(**kw):
        i = IN(kw.pop("type"));
        if i.type == 0: i.u.mi = MI(kw.get("dx", 0), kw.get("dy", 0), 0, 0x0001, 0, 0)          # MOUSEEVENTF_MOVE (relative)
        else: i.u.ki = KI(kw["vk"], u32.MapVirtualKeyW(kw["vk"], 0), 2 if kw.get("up") else 0, 0, 0)
        return u32.SendInput(1, ctypes.byref(i), ctypes.sizeof(i))
    before = state(); sent = 0
    try:
        k32.SetThreadExecutionState(0x00000003)                                      # ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED, one shot: resets the display / sleep idle timers
        u32.SendMessageTimeoutW(0xFFFF, 0x0112, 0xF170, -1, 2, 1500, None)           # WM_SYSCOMMAND SC_MONITORPOWER -1: monitor on
        u32.SystemParametersInfoW(0x1021, 0, None, 0)                                # SPI_SETMOUSEVANISH off (runtime only, not saved): the pointer is not hidden "while typing"
        u32.SystemParametersInfoW(0x57, 0, None, 0)                                  # SPI_SETCURSORS: reload the cursor set
        for kw in ({"type": 0, "dx": 1}, {"type": 0, "dx": -1}, {"type": 1, "vk": 0x10}, {"type": 1, "vk": 0x10, "up": True}):
            sent += 1 if send(**kw) else 0; time.sleep(0.06)
    except Exception as e: log(f"prime: {e!r}")
    time.sleep(0.4); after = state()
    log(f"prime input: {sent}/4 events accepted | pointer flags {before[0]}->{after[0]} (1 = shown) | idle {before[1]:.0f}s -> {after[1]:.0f}s (-1 = Windows had no input yet)")
_prime_at = [0.0]
def prime_input(why=""):
    """Agent: run the --primeinput helper on the signed-in desktop (at most once every 3 s). -> True if it was started."""
    if time.time() - _prime_at[0] < 3: return True
    _prime_at[0] = time.time()
    if is_locked(): log(f"prime input ({why}): skipped, the sign-in / lock screen is showing"); return False
    try: spawn_in_console_session(helper_cmd("--primeinput"), r"winsta0\default"); log(f"prime input started ({why})"); return True
    except Exception as e: log(f"prime input ({why}) failed: {e}"); return False
def verify_pin_via_lock(user, pin):
    """Let WINDOWS check a PIN for a user who is signed in: lock their session, type the PIN at the lock screen, see whether it unlocks. One attempt."""
    ids = [s["id"] for s in sessions() if s["user"].lower() == user.lower()]
    if not ids: return False, f"{user} is not signed in"
    sid = ids[0]; log(f"lock check: session {sid}, lock screen showing = {is_locked()}")
    if not is_locked():
        try: spawn_in_console_session("rundll32.exe user32.dll,LockWorkStation", r"winsta0\default")
        except Exception as e: log(f"lock check: could not lock: {e}"); return False, f"Could not lock the PC to check the PIN: {e}"
        for _ in range(20):
            time.sleep(0.5)
            if is_locked(): break
        else: log("lock check: the lock screen never appeared"); return False, "Could not lock the PC to check the PIN"
    time.sleep(1.5); log("lock check: PC is locked, typing the PIN")
    f = os.path.join(APPDIR, f"pin_{secrets.token_hex(4)}.tmp"); _write_private(f, pin)
    try: spawn_in_console_session(helper_cmd(f'--typepin "{f}"'))
    except Exception as e:
        try: os.remove(f)
        except OSError: pass
        log(f"lock check: could not start the typing helper: {e}"); return False, f"Could not reach the lock screen: {e}"
    for _ in range(50):                                                     # unlocked = the lock screen has gone away
        time.sleep(0.5)
        if not is_locked() and any(x["user"].lower() == user.lower() for x in sessions()):
            salt = secrets.token_bytes(16); pr = _proof_load(); pr[user.lower()] = {"salt": salt.hex(), "hash": _pbkdf(pin, salt)}
            _write_private(PROOF, json.dumps(pr)); log(f"Windows accepted the PIN for {user} at the lock screen"); return True, "PIN accepted by Windows"
    _fail.append(time.time()); log(f"Windows did not unlock the session (lock screen still showing = {is_locked()})")
    return False, "Windows did not accept that PIN (the PC is left locked - unlock it with the right PIN)"
def rpc_pin(cmd, user, pin, ip):
    if not 4 <= len(pin) <= 127: return {"ok": False, "msg": "A Windows PIN is at least 4 characters"}
    if locked_out(): return lock_resp()
    if cmd == "verify":
        m = pin_matches(user, pin)
        return {"ok": True, "checked": bool(m), "msg": "PIN matches" if m else "This PIN cannot be checked before it is used"}
    log(f"{cmd} {user} from {ip} (PIN)")
    try:
        with _login_lock:
            if cmd == "login": ok, msg = do_login_pin(user, pin)
            else:                                                       # sign-out: a PIN Windows already accepted is enough; any other PIN must pass Windows' own check
                ok, msg = (True, "") if pin_matches(user, pin) else verify_pin_via_lock(user, pin)
                if ok: ok, msg = do_logoff(user)
    except Exception as e: ok, msg = False, str(e)
    return {"ok": ok, "msg": msg}
def rpc_hostpin(cmd, user, pin, ip):
    """Accounts that have a remote PIN: ONLY that PIN authorises sign-in / sign-out. The Windows side of these accounts has no password."""
    if locked_out(): return lock_resp()
    if not hostpin_ok(user, pin):
        _fail.append(time.time()); log(f"{cmd} for {user} from {ip}: wrong remote PIN")
        return {"ok": False, "msg": "That PIN is wrong (it is the PIN set for this account in WoL Host > Remote PIN)"}
    log(f"{cmd} {user} from {ip} (remote PIN)")
    try:
        with _login_lock:
            if cmd == "verify": ok, msg = True, "PIN is correct"
            elif cmd == "login": ok, msg = do_login_typed(user, "", "blank")
            else: ok, msg = do_logoff(user)
    except Exception as e: ok, msg = False, str(e)
    return {"ok": ok, "msg": msg, **({"checked": True} if cmd == "verify" and ok else {})}
def rpc_dual(cmd, user, pin, pw, ip):
    """Accounts that keep their Windows / Microsoft password AND have a remote PIN: the PIN alone signs them out; signing in needs the PIN and the password."""
    if locked_out(): return lock_resp()
    if not hostpin_ok(user, pin):
        _fail.append(time.time()); log(f"{cmd} for {user} from {ip}: wrong remote PIN")
        return {"ok": False, "msg": "That PIN is wrong (it is the PIN set for this account in WoL Host > Remote PIN)"}
    if cmd == "verify": return {"ok": True, "checked": True, "msg": "PIN is correct"}
    if cmd == "logoff":
        log(f"logoff {user} from {ip} (remote PIN)")
        try:
            with _login_lock: ok, msg = do_logoff(user)
        except Exception as e: ok, msg = False, str(e)
        return {"ok": ok, "msg": msg}
    if not pw: return {"ok": False, "msg": "Signing this account in needs its PIN and its Windows password. Enter both."}
    if not is_msa(user):                                                 # local account: pre-check the password so a typo never reaches the sign-in screen
        vok, e = logon_check(user, pw)
        if not vok:
            if e != 1326:                                                # (1326 can be a false alarm on some PCs: Windows' own sign-in screen is then the judge)
                _fail.append(time.time()); log(f"login pre-check failed for {user} from {ip} (error {e})")
                return {"ok": False, "msg": LOGON_MSG.get(e, f"Windows rejected the logon (error {e})")}
    log(f"login {user} from {ip} (remote PIN + password)")                # the password is never logged
    try:
        with _login_lock: ok, msg = do_login_typed(user, pw, "password")
    except Exception as e: ok, msg = False, str(e)
    return {"ok": ok, "msg": msg}
def rpc(d, ip):
    cmd = d.get("cmd")
    if cmd not in ("verify", "login", "logoff"): return {"ok": False, "msg": "unknown command"}
    user, pw = str(d.get("user", "")), str(d.get("pw", ""))
    if has_hostpin(user) and hostpin_mode(user) == "dual": return rpc_dual(cmd, user, str(d.get("pin") or ""), pw, ip)
    if has_hostpin(user) and not is_msa(user): return rpc_hostpin(cmd, user, str(d.get("pin") or d.get("pw") or ""), ip)       # remote PIN set in TimeGuard (an older client sends it as "pw": same thing)
    if "pin" in d and is_msa(user): return rpc_pin(cmd, user, str(d["pin"]), ip)           # Microsoft account: Windows PIN, no password
    if not pw: return {"ok": False, "msg": "This account has no remote PIN yet. Set one in WoL Host > Remote PIN (needed once its Windows password is removed)."}     # never let an empty password pass for a blank-password account
    if locked_out(): return lock_resp()
    vok, e = logon_check(user, pw)                                      # every command is authorised by that Windows account's own password
    if not vok:
        _fail.append(time.time()); log(f"{cmd} pre-check failed for {user} from {ip} (error {e})")
        if e == 1326 and cmd in ("login", "verify"):                    # LogonUser can say 1326 for a correct password on some PCs: let Windows' sign-in screen decide (sign-out stays strict)
            if cmd == "verify": return {"ok": True, "checked": False, "msg": "Could not be pre-checked here - Windows checks it at sign-in"}
            vok = True
        else: return {"ok": False, "msg": LOGON_MSG.get(e, f"Windows rejected the logon (error {e})")}
    log(f"{cmd} {user} from {ip}")                                     # the password is never logged
    try:
        with _login_lock: ok, msg = {"verify": lambda: (True, "Password is correct"), "login": lambda: do_login(user, pw), "logoff": lambda: do_logoff(user)}[cmd]()
    except Exception as e: ok, msg = False, str(e)
    return {"ok": ok, "msg": msg, **({"checked": True} if cmd == "verify" and ok else {})}

# ---------------- Sunshine (the stream host Moonlight connects to) ----------------
SUN_DIR = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Sunshine")
SUN_EXE = os.path.join(SUN_DIR, "sunshine.exe")
SUN_SVC, SUN_PORT, SUN_UI = "SunshineService", 47989, 47990     # Windows service (runs at boot as SYSTEM) / stream+pairing port / local web UI+API
CREDS = os.path.join(APPDIR, "sunshine.json")                  # API login that setup created; locked down to SYSTEM + Administrators
def sun_installed(): return os.path.exists(SUN_EXE)
def sun_up():
    try: socket.create_connection(("127.0.0.1", SUN_PORT), 1).close(); return True
    except Exception: return False
def sun_creds():
    try: d = json.load(open(CREDS, encoding="utf-8")); return d["user"], d["pw"]
    except Exception: return None
def sun_api(path, body=None, creds=None, timeout=6):
    """Call Sunshine's local web API (self-signed HTTPS on localhost only). -> (http status, json dict)"""
    u, p = creds or sun_creds() or ("", "")
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(f"https://127.0.0.1:{SUN_UI}{path}", data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r: code, raw = r.status, r.read()
    except urllib.error.HTTPError as e: code, raw = e.code, e.read()
    try: return code, json.loads(raw or b"{}")
    except Exception: return code, {}
def sun_pair(pin, name):
    """Enter the PIN a Moonlight client is showing into Sunshine (the client app sends it over Tailscale)."""
    if not re.fullmatch(r"\d{4}", pin): return "ERR bad PIN"
    if not sun_creds(): return "ERR Sunshine is not set up - run WoL Host setup on the PC"
    try: code, d = sun_api("/api/pin", {"pin": pin, "name": (name or "WoL Remote")[:40]})
    except Exception as e: return f"ERR {e!r}"[:120]
    _cc["t"] = 0.0                                                      # the paired list is about to change: never answer from the cache
    return "OK" if code == 200 and d.get("status") else "ERR Sunshine refused the PIN (no pairing in progress?)"
# ---------------- connections: who talks to this PC, and who is paired with Sunshine ----------------
CLIENTS = os.path.join(APPDIR, "clients.json")                 # {tailscale ip: {first, last, kinds[], blocked}} - written by the agent
SEEN_LIVE = 45                                                  # a client that asked something in the last 45 s counts as connected now
_cl_lock = threading.Lock()
def _cl_load():
    try: d = json.load(open(CLIENTS, encoding="utf-8")); return d if isinstance(d, dict) else {}
    except Exception: return {}
def _cl_save(d):
    os.makedirs(APPDIR, exist_ok=True); tmp = CLIENTS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: f.write(json.dumps(d))
    os.replace(tmp, CLIENTS)
def client_seen(ip, kind):
    """Agent: note that this Tailscale client just talked to us. Returns True if the client is blocked (the caller then drops the connection)."""
    if ip == "127.0.0.1": return False
    with _cl_lock:
        d = _cl_load(); now = time.time(); e = d.get(ip)
        if e is None: e = d[ip] = {"first": now, "last": 0, "kinds": []}
        if now - e.get("last", 0) >= 10 or kind not in e.setdefault("kinds", []):          # throttle: at most one disk write per client per 10 s
            e["last"] = now
            if kind not in e["kinds"]: e["kinds"].append(kind)
            try: _cl_save(d)
            except Exception as ex: log(f"clients.json: {ex!r}")
        return bool(e.get("blocked"))
def client_set(ip, **kw):
    """GUI: block / unblock (blocked=True/False) or forget (remove=True) a client."""
    with _cl_lock:
        d = _cl_load()
        if kw.get("remove"): d.pop(ip, None)
        elif ip in d: d[ip].update(kw)
        _cl_save(d)
def ts_peers():
    """Tailscale IP -> {name, os} of every device on the tailnet (cached 20 s)."""
    if "peers" in _cache and time.time() - _cache["peers"][0] < 20: return _cache["peers"][1]
    out = {}
    try:
        rc, txt = sh(f'"{tsexe()}" status --json', 20)
        d = json.loads(txt) if rc == 0 else {}
        me = d.get("Self") or {}
        for pe in list((d.get("Peer") or {}).values()) + [me]:
            for a in pe.get("TailscaleIPs") or []: out[a] = {"name": pe.get("HostName") or (pe.get("DNSName") or "").split(".")[0], "os": pe.get("OS") or "", "online": bool(pe.get("Online")) or pe is me, "self": pe is me}
    except Exception as e: log(f"tailscale status: {e!r}")
    _cache["peers"] = (time.time(), out); return out
def ts_account(force=False):
    """This PC's Tailscale login, read from `tailscale status --json` (cached 30 s): {"state", "login" (e-mail account), "name", "tailnet" (network name)}. {} when Tailscale does not answer."""
    if not force and "acct" in _cache and time.time() - _cache["acct"][0] < 30: return _cache["acct"][1]
    out = {}
    try:
        d = json.loads(_run([tsexe(), "status", "--json"], capture_output=True, text=True, timeout=20).stdout)
        me = d.get("Self") or {}; u = (d.get("User") or {}).get(str(me.get("UserID"))) or {}
        out = {"state": d.get("BackendState") or "", "login": u.get("LoginName") or "", "name": u.get("DisplayName") or "", "tailnet": (d.get("CurrentTailnet") or {}).get("Name") or ""}
    except Exception as e: log(f"tailscale account: {e!r}")
    _cache["acct"] = (time.time(), out); return out
def ts_label(a=None):
    """What to show next to "connected": the e-mail account of the Tailscale login, or the name of the tailnet (a key from the phone's account is often 'tagged' and has no e-mail)."""
    a = ts_account() if a is None else a
    lg = a.get("login") or ""
    return lg if "@" in lg else (a.get("tailnet") or a.get("name") or "")
def paired_computers():
    """Computers that are paired with THIS PC and are online on the tailnet right now. -> [{name, ip, os, live}]
    Paired = the computer paired through this PC's agent (clients.json remembers it), or Sunshine holds a "WoL Remote (<computer name>)" device for it."""
    peers, cl, now = ts_peers(), _cl_load(), time.time()
    sun_client_count(); names = _cc.get("names") or []
    by_sunshine = {n[len("WoL Remote ("):-1].strip().lower() for n in names if n.startswith("WoL Remote (") and n.endswith(")")}
    out = []
    for ip, p in peers.items():
        if p.get("self") or not p.get("online") or ":" in ip: continue                  # only other computers that are online now (one row per device: skip its IPv6 address)
        e = cl.get(ip) or {}
        if "pair" in (e.get("kinds") or []) or (p.get("name") or "").strip().lower() in by_sunshine:
            out.append({"name": p.get("name") or ip, "ip": ip, "os": p.get("os") or "", "live": now - e.get("last", 0) < SEEN_LIVE})
    return sorted(out, key=lambda x: x["name"].lower())
def sun_clients():
    """Clients paired with the running Sunshine. -> (ok, [{name, uuid}]) or (False, reason)"""
    if not sun_installed(): return False, "Sunshine is not installed on this PC"
    if not sun_up(): return False, "Sunshine is not running (it only runs while someone is signed in)"
    if not sun_creds(): return False, "Sunshine is not set up - run Set up first"
    try: code, d = sun_api("/api/clients/list")
    except Exception as e: return False, f"Could not ask Sunshine: {e}"
    if code != 200: return False, f"Sunshine refused the request (HTTP {code}) - press UPDATE on This PC"
    return True, [{"name": c.get("name") or "(unnamed)", "uuid": c.get("uuid", "")} for c in d.get("named_certs", [])]
def sun_unpair(uuid=None):
    """Forget one paired client (or all of them when uuid is None). -> (ok, message)"""
    _cc["t"] = 0.0
    try: code, d = sun_api("/api/clients/unpair-all", {}) if uuid is None else sun_api("/api/clients/unpair", {"uuid": uuid})
    except Exception as e: return False, str(e)
    return (code == 200 and d.get("status") is not False), ("" if code == 200 else f"Sunshine answered HTTP {code}")
_cc = {"t": 0.0, "n": None, "names": None}
def sun_client_count():
    """How many clients Sunshine says are paired with it, or None when it cannot be asked. 0 means its pairing list is empty (state file lost / reset).
    Also remembers the paired clients' names in _cc["names"] (None = could not be asked)."""
    if _cc["n"] and time.time() - _cc["t"] < 5: return _cc["n"]
    try:
        if not (sun_up() and sun_creds()): n, names = None, None
        else:
            code, d = sun_api("/api/clients/list", timeout=2)
            if code == 200: names = [c.get("name") or "" for c in d.get("named_certs", [])]; n = len(names)
            else: n, names = None, None
    except Exception: n, names = None, None
    _cc.update(t=time.time(), n=n, names=names); return n
SUN_TASK = "WoLHostSunshine"
_sun_lock, _sun_t = threading.Lock(), [0.0]
def sun_start():
    """Sunshine runs inside a signed-in user's session, never as a boot service - so nothing can stream the sign-in screen.
    It runs as SYSTEM in that session (what Sunshine's own service does): input that Sunshine injects as a normal user is dropped by Windows (UIPI) while an
    admin / elevated window has the focus, so the stream would stop reacting. As SYSTEM it reaches every window, UAC prompts included.
    -> True if it is up. (False at the sign-in screen is intended.)"""
    if sun_up(): return True
    if not has_session(): return False
    with _sun_lock:
        if sun_up(): return True
        if time.time() - _sun_t[0] > 25:                                    # not started a moment ago (a start can take a few seconds to open its port)
            _sun_t[0] = time.time()
            if is_system():
                if not sun_launch(): return False
            else:                                                           # the setup window runs as an administrator, not SYSTEM: a one-shot SYSTEM task does the launch
                cmd = helper_cmd("--sunlaunch")
                rc, out = sh(f'schtasks /create /tn WoLHostSunLaunch /tr "{cmd.replace(chr(34), chr(92) + chr(34))}" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f', 30)
                if rc != 0: log(f"sunshine start: could not create the launch task: {out[:120]}"); return False
                sh("schtasks /run /tn WoLHostSunLaunch", 20)
        for _ in range(100):
            if sun_up(): return True
            time.sleep(0.5)
    return False
def is_system():
    try:
        buf = ctypes.create_unicode_buffer(256); n = ctypes.c_ulong(256)
        ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(n)); return buf.value.upper() == "SYSTEM"
    except Exception: return False
def sun_launch():
    """(SYSTEM only) Wait for the signed-in user's desktop, then start Sunshine as SYSTEM in that session."""
    for _ in range(30):                                                     # a Sunshine that came up before the user's desktop existed can have dead mouse / keyboard input
        if shell_up(): break
        time.sleep(1)
    else: log("sunshine start: the user's desktop is not up yet"); return False
    time.sleep(2)
    try: spawn_in_console_session(f'"{SUN_EXE}"', r"winsta0\default", SUN_DIR); log("sunshine started as SYSTEM in the signed-in session"); return True
    except Exception as e: log(f"sunshine start failed: {e}"); return False
def sun_launch_main(): sun_launch()                                         # helper `--sunlaunch`, run by the one-shot SYSTEM task
def sun_task():
    """Scheduled task: start Sunshine when ANY user signs in, inside that user's session; gone again when they sign out."""
    vbs = os.path.join(APPDIR, "sunshine_launch.vbs")                    # sunshine.exe is a console program: run it hidden, and wait so the task owns it
    # Sunshine must not start in the middle of the sign-in: a Sunshine that came up before the user's desktop existed can end up with dead mouse / keyboard input.
    # So the launcher first waits (max 60 s) until explorer.exe runs, plus 3 s, and only then starts it.
    wait = 'On Error Resume Next\nSet wmi = GetObject("winmgmts:\\\\.\\root\\cimv2")\nFor i = 1 To 60\n  If wmi.ExecQuery("select ProcessId from Win32_Process where Name=\'explorer.exe\'").Count > 0 Then Exit For\n  WScript.Sleep 1000\nNext\nWScript.Sleep 3000\nOn Error GoTo 0\n'
    with open(vbs, "w", encoding="utf-8") as f: f.write('Set sh = CreateObject("WScript.Shell")\n' + wait + f'sh.CurrentDirectory = "{SUN_DIR}"\nsh.Run """{SUN_EXE}""", 0, True\n')
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><StartWhenAvailable>true</StartWhenAvailable>
    <RestartOnFailure><Interval>PT1M</Interval><Count>99</Count></RestartOnFailure><Enabled>false</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>wscript.exe</Command><Arguments>//B //nologo "{vbs}"</Arguments><WorkingDirectory>{SUN_DIR}</WorkingDirectory></Exec></Actions>
</Task>"""
    os.makedirs(APPDIR, exist_ok=True); xp = os.path.join(APPDIR, "sunshine_task.xml")
    with open(xp, "w", encoding="utf-16") as f: f.write(xml)
    return sh(f'schtasks /create /tn {SUN_TASK} /xml "{xp}" /f', 30)
def idle_info():
    """The TimeGuard engine's countdowns, for WoL Remote: {"login": seconds until the sign-in-screen shutdown | None, "users": {name: seconds until the inactivity sign-out}}.
    Values are corrected for the age of the status file; nothing is reported when the engine is not running (file older than 30 s)."""
    try:
        d = json.load(open(os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "TimeGuard", "inactive.json"), encoding="utf-8"))
        age = max(time.time() - float(d.get("ts", 0)), 0.0)
        if age > 120: return None                                            # the engine's round can take long (PowerShell account lookups); values are corrected for age anyway
        lg = d.get("login")
        return {"why": d.get("why") or {}, "login": None if lg is None else max(float(lg) - age, 0.0),
                "users": {str(k).lower(): (-1.0 if v is None or float(v) < 0 else max(float(v) - age, 0.0)) for k, v in (d.get("users") or {}).items()}}
    except Exception: return None
TGDIR = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "TimeGuard")
_tga, _tgc = {"t": 0.0, "n": None, "busy": False}, {"t": 0.0, "v": {}}
def _tg_admins():
    """Lower-case names of the administrator accounts (TimeGuard never limits them). Looked up in the background (PowerShell is slow), refreshed every minute; None = not known yet."""
    now = time.time()
    if now - _tga["t"] > 60 and not _tga["busy"]:
        _tga["t"] = now; _tga["busy"] = True
        def f():
            try:
                r = _run(["powershell", "-NoProfile", "-Command", "@(Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join '|'"], capture_output=True, text=True, timeout=40)
                names = {x.split("\\")[-1].strip().lower() for x in r.stdout.strip().split("|") if x.strip()}
                if names: _tga["n"] = names
            except Exception as e: log(f"timeguard: administrator lookup failed: {e!r}")
            finally: _tga["busy"] = False
        threading.Thread(target=f, daemon=True).start()
    return _tga["n"]
def _tg_left(u, usage, now):
    """(seconds left or None = unlimited, what limits it) - the same rules as TimeGuard's remaining_info: balance, weekly, monthly, allowed hours."""
    today, left = now.date(), []
    used = lambda d: usage.get(d.isoformat(), 0)
    if u.get("credit_min") is not None: left.append((u["credit_min"] * 60 - usage.get("_total", sum(v for k, v in usage.items() if k[:2] == "20")), "balance"))
    if u.get("weekly"):
        mon = today - datetime.timedelta(days=today.weekday()); left.append((u["weekly"] * 60 - sum(used(mon + datetime.timedelta(days=i)) for i in range(7)), "weekly"))
    if u.get("monthly"):
        ym = today.isoformat()[:7]; left.append((u["monthly"] * 60 - sum(v for k, v in usage.items() if k[:7] == ym), "monthly"))
    if u.get("use_schedule"):
        f = datetime.datetime.combine(today, datetime.time.fromisoformat(u["from"])); t = datetime.datetime.combine(today, datetime.time.fromisoformat(u["to"]))
        ok, end = (f <= now < t, t) if f <= t else (now >= f or now < t, t if now < t else t + datetime.timedelta(days=1))
        left.append(((end - now).total_seconds(), "hours:" + end.strftime("%H:%M")) if ok else (0, "closed:" + u["from"]))
    return min(left, key=lambda x: x[0]) if left else (None, None)
def tg_info():
    """TimeGuard time left for WoL Remote: {user (lower case): {"left": seconds (limited accounts only), "by": what limits it, "run": signed in right now = the time is running down}}.
    Only accounts TimeGuard manages (Accounts > Manage on) and never administrators. Read from TimeGuard's own files; {} when TimeGuard is not set up."""
    now_t = time.time()
    if now_t - _tgc["t"] < 2: return _tgc["v"]
    _tgc["t"] = now_t; out = {}
    try:
        ld = lambda f: json.load(open(os.path.join(TGDIR, f), encoding="utf-8"))
        users = (ld("config.json").get("users") or {})
        if users:
            usage = ld("usage.json"); adm = _tg_admins(); active = {x["user"].lower() for x in sessions() if x["state"] == "active"}; here = {x["user"].lower() for x in sessions()}
            try: st = ld("status.json")
            except Exception: st = {}
            try: age = max(now_t - os.path.getmtime(os.path.join(TGDIR, "usage.json")), 0.0)
            except Exception: age = 0.0
            for name, u in users.items():
                key = name.lower()
                if not u.get("enabled") or (adm is not None and key in adm) or (adm is None and key not in st): continue         # an administrator is never limited; unknown yet = only accounts the engine already tracks
                left, by = _tg_left(u, usage.get(name) or usage.get(key) or {}, datetime.datetime.now())
                if left is None: continue
                if key in active and age < 60: left -= age                      # usage.json is rewritten every few seconds: the time that has passed since is already used up
                out[key] = {"left": max(float(left), 0.0), "by": by or "", "run": key in active, "in": key in here}
    except Exception: out = {}
    _tgc["v"] = out; return out
PCNAME_F = os.path.join(APPDIR, "pcname.txt")
def pc_label():
    """The name this PC shows in WoL Remote. Only set here (WoL Host > This PC > PC name); the client app cannot change it."""
    try: return open(PCNAME_F, encoding="utf-8").read().strip()[:40]
    except Exception: return ""
def set_pc_label(name):
    name = (name or "").strip()[:40]
    os.makedirs(APPDIR, exist_ok=True)
    if name: open(PCNAME_F, "w", encoding="utf-8").write(name)
    else:
        try: os.remove(PCNAME_F)
        except OSError: pass
    return name
def keep_awake():
    """The PC must not go to sleep - not at the sign-in screen after a boot either (nobody could wake it from WoL Remote then). The agent starts at boot, so a thread that
    keeps SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) set holds Windows awake for as long as the agent runs (the screen may still turn off)."""
    def run():
        while True:
            try: ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)
            except Exception as e: log(f"keep awake: {e!r}")
            time.sleep(30)
    threading.Thread(target=run, daemon=True).start()
def info_dict(me):
    return {"name": socket.gethostname(), "label": pc_label() or socket.gethostname(), "ip": me if me.startswith("100.") else ts_ip(), "macs": _cache["mm"][1] if "mm" in _cache else macs_cached(),
            "wol_macs": _cache["wm"][1] if "wm" in _cache else [], "ips": _cache["li"][1] if "li" in _cache else lan_ips_cached(),
            "users": _cache["u"][1] if "u" in _cache else [], "msa": _cache["m"][1] if "m" in _cache else [], "hostpin": hostpin_users(), "pinmode": hostpin_dual_users(), "access_pin": {"required": bool(accesspin_active()), "exp": 0}, "login_fail": login_fail(), "idle": idle_info(), "tg": tg_info(), "sessions": [{"user": s["user"], "state": s["state"]} for s in sessions()], "disk_free_mb": disk_free_mb(),
            "sunshine": {"installed": sun_installed(), "running": sun_up(), "pairing": bool(sun_creds()), "port": SUN_PORT, "clients": sun_client_count(), "client_names": _cc.get("names")}}
def _serve():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(("0.0.0.0", HPORT)); srv.listen(8)
    log(f"agent listening on {HPORT}")
    def handle(c, ip):
        try:
            p = ip.split(".")
            if not (ip == "127.0.0.1" or (p[0] == "100" and 64 <= int(p[1]) <= 127)): return
            c.settimeout(4)
            line = c.makefile().readline().strip()
            apin = ""
            if line.startswith("@"):                           # "@<access PIN>@<command>": the access PIN rides in front of a one-line command
                m = re.match(r"@(\d{1,32})@(.*)$", line, re.S)
                if m: apin, line = m.group(1), m.group(2)
            if client_seen(ip, "pair" if line.startswith("pair|") else "sign-in" if line.startswith("{") else "info"): log(f"blocked client {ip} refused"); return
            code = access_check(apin) if (line.startswith(("pair|", "{")) or line in ("prime", "shutdown", "sunstart")) and not line.startswith("{") else None
            if code:                                       # access PIN missing / wrong: nothing below is done
                c.sendall((("ERR " + code if code != "LOCKED" else "ERR " + access_msg(code)) + "\n").encode())
            elif line.startswith("pair|"):
                parts = (line.split("|", 2) + ["", ""])[:3]; log(f"pair request from {ip}")
                c.settimeout(20); c.sendall((sun_pair(parts[1], parts[2]) + "\n").encode())
            elif line.startswith("{"):
                d = json.loads(line); code = access_check(str(d.get("apin") or ""))
                if code: out = {"ok": False, "msg": access_msg(code), **({"needpin": code} if code != "LOCKED" else {"wait": access_wait()})}
                elif d.get("cmd") == "accesscheck": out = {"ok": True, "required": bool(accesspin_active())}
                else: out = rpc(d, ip)
                c.settimeout(60); c.sendall((json.dumps(out) + "\n").encode())
            elif line == "prime":                          # the PC app asks (right before it opens Moonlight): wake the session's mouse / keyboard input
                c.sendall((("OK" if prime_input("client request") else "ERR nobody signed in, or the screen is locked") + "\n").encode())
            elif line == "shutdown":                       # the PC app's Shut down button: only while nobody is signed in (re-checked here, the app's view can be seconds old)
                ss = sessions()
                if ss: log(f"shutdown from {ip} refused: {ss[0]['user']} is signed in"); c.sendall(f"ERR {ss[0]['user']} is signed in\n".encode())
                else:
                    log(f"shutdown requested by {ip}: nobody is signed in"); c.sendall(b"OK\n")
                    _stale_checked[0] = 0.0; stale_autologon()          # make sure auto-logon is OFF before the PC goes down, so the next start shows the sign-in screen
                    _run(["shutdown", "/s", "/t", "15", "/c", "WoL Remote: shutting down in 15 seconds."], capture_output=True)
                    def guard():                           # somebody signs in during the 15 s: cancel
                        for _ in range(12):
                            time.sleep(1)
                            if sessions(): _run(["shutdown", "/a"], capture_output=True); log("shutdown cancelled: a user signed in"); return
                    threading.Thread(target=guard, daemon=True).start()
            elif line == "sunstart":                       # the PC app asks: make sure Sunshine is running in the signed-in session
                c.settimeout(60); log(f"sunshine start requested by {ip}")
                c.sendall((("OK" if sun_start() else "ERR Sunshine did not start (nobody signed in, or it is not installed)") + "\n").encode())
            elif line == "info":
                c.sendall((json.dumps(info_dict(c.getsockname()[0])) + "\n").encode())          # c.getsockname: the Tailscale IP the client used to reach this PC
        except Exception as e: log(f"handler error: {e!r}")
        finally: c.close()
    while True:
        c, a = srv.accept(); threading.Thread(target=handle, args=(c, a[0]), daemon=True).start()
def agent():
    log(f"agent starting (python {sys.version.split()[0]}, exe {sys.executable})")
    keep_awake()
    threading.Thread(target=access_sync_loop, daemon=True).start()                     # access PIN: expires on time, phone kept in step
    threading.Thread(target=host_register_loop, daemon=True).start()                   # tells the phone (and through it the WoL Remote PCs) this PC's Tailscale IP + MACs until it is confirmed
    threading.Thread(target=lambda: sh(f"schtasks /change /tn {SUN_TASK} /disable", 20), daemon=True).start()      # Sunshine is started by the agent now (as SYSTEM), not by the old logon task
    threading.Thread(target=lambda: (macs_cached(True), lan_ips_cached(True)), daemon=True).start()                  # warm the caches: the first client request after boot must be fast
    threading.Thread(target=lambda: (any(ts_ip() or time.sleep(10) for _ in range(30)), ts_ip() and ensure_unattended()), daemon=True).start()
    def refresher():                 # PowerShell is slow, so it only ever runs here - client requests are answered from the cache instantly
        n = 0
        while True:
            try:
                macs_cached(); lan_ips_cached()                              # keep the answers of the "who are you?" request fresh (never done while a client waits)
                users(True)                                                  # first: the client needs the "msa" list to choose PIN vs password (every 10 s: new / removed accounts show up quickly)
                if n % 12 == 0:                                              # the slow things stay at 2 minutes
                    if sun_installed() and not sun_up() and has_session(): log("Sunshine not running in the signed-in session - starting it"); sun_start()
                    physical_macs(True)
                    if ts_ip() and ts_unattended(True) is False: log("Tailscale is not in unattended mode - fixing"); ensure_unattended()
                    if 0 <= disk_free_mb() < 1024: log(f"LOW DISK: only {disk_free_mb()} MB free on the system drive - Sunshine pairings and logs may fail to save")
            except Exception as e: log(f"refresh error: {e!r}")
            n += 1; time.sleep(10)
    def watcher():                   # fast loop: wipe the auto-logon password the moment a remote sign-in has worked
        last, starting = 0, threading.Event()
        pr = {"key": None, "t0": 0.0, "n": 0, "sun": False}          # input priming of the current session: shots 0 s, 12 s, 30 s after its desktop is up, and when Sunshine appears
        def prime_tick():
            ss = sessions()
            if not ss: pr.update(key=None, n=0, sun=False); return
            key = (ss[0]["id"], ss[0]["user"].lower())
            if key != pr["key"]: pr.update(key=key, t0=0.0, n=0, sun=False)      # a new session
            if not pr["t0"]:
                if not shell_up(): return
                pr["t0"] = time.time(); log(f"desktop of {ss[0]['user']} is up - waking its input")
            up = sun_up(); due = pr["n"] < 3 and time.time() - pr["t0"] >= (0, 12, 30)[pr["n"]]
            if due or (up and not pr["sun"]):
                pr["n"] += 1 if due else 0; pr["sun"] = up
                prime_input("new session" if due else "Sunshine started")
        def bring_up():
            try: sun_start()
            finally: starting.clear()
        empty = 0
        while True:
            try:
                pending_tick(); pin_tick(); prime_tick()
                empty = 0 if has_session() else empty + 1
                if empty == 2 and sun_up(): log("nobody is signed in any more: stopping Sunshine"); sh("taskkill /f /im sunshine.exe", 20)    # a SYSTEM Sunshine must never stay up at the sign-in screen
                if time.time() - last > 15 and not starting.is_set():          # someone just signed in and Sunshine is not up: start it within seconds, not minutes
                    last = time.time()
                    if sun_installed() and has_session() and not sun_up(): log("signed-in user has no Sunshine - starting it"); starting.set(); threading.Thread(target=bring_up, daemon=True).start()
            except Exception as e: log(f"watcher error: {e!r}")
            time.sleep(5)
    agent_key(); threading.Thread(target=refresher, daemon=True).start(); threading.Thread(target=watcher, daemon=True).start()
    while True:                      # never die silently: log the error and retry
        try: _serve()
        except Exception as e: log(f"agent crashed: {e!r} - retrying in 5s"); time.sleep(5)

# ---------------- setup steps: each returns (ok, message) ----------------
# ---------------- keep the data off a full C: drive ----------------
# Everything the agent writes lives under APPDIR (C:\ProgramData\WoLHost) and Sunshine keeps its pairings, logs and certificates in <Sunshine>\config.
# Both folders are moved to DATA_DRIVE and a junction is left at the old path, so every program keeps using the old path and really writes to the new drive.
DATA_DRIVE = os.environ.get("WOL_DATA_DRIVE", "D:")                   # set WOL_DATA_DRIVE to another drive letter, or to an empty value to keep everything on C:
SECRET_FILES = ("agent.key", "sunshine.json", "pin_proof.json", "pending_pin.json", "host_pins.json", "pending_login.json", "login_fail.json")
def _is_junction(p):
    try: return os.path.isdir(p) and os.path.normcase(os.path.realpath(p)) != os.path.normcase(os.path.abspath(p))
    except Exception: return False
def relocate(src, dst):
    """Move folder `src` to `dst` (another drive) and leave a junction at `src`. Nothing is needed on the old drive: copy first, delete the old folder, then link. -> (ok, message)"""
    src, dst = os.path.abspath(src), os.path.abspath(dst)
    if _is_junction(src): return True, f"{src} already lives on {os.path.realpath(src)}"
    os.makedirs(dst, exist_ok=True)
    if os.path.isdir(src):
        r = _run(["robocopy", src, dst, "/E", "/XO", "/COPY:DAT", "/R:1", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP"], capture_output=True, text=True, timeout=1800)
        if r.returncode >= 8: return False, f"Copying {src} to {dst} failed (robocopy code {r.returncode})"
        try: shutil.rmtree(src)
        except OSError as e: return False, f"Copied {src} to {dst}, but the old folder is in use ({str(e)[:80]}). Close WoL Host, then run as administrator: python wol_host.py --move-data"
    else: os.makedirs(os.path.dirname(src), exist_ok=True)
    rc, out = sh(f'mklink /J "{src}" "{dst}"', 20)
    return (True, f"{src} now lives on {dst}") if rc == 0 else (False, f"Could not link {src} to {dst}: {out[:120]}")
def relock_appdir(path):
    """robocopy carries no permissions: give the folder ProgramData's usual rights (Users may read - the Sunshine launcher runs as them) and lock the secrets to SYSTEM + Administrators again."""
    sh(f'icacls "{path}" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX', 30)
    try: names = list(SECRET_FILES) + [f for f in os.listdir(path) if f.startswith("pin_") and f.endswith(".tmp")]
    except OSError: names = list(SECRET_FILES)
    for n in names:
        p = os.path.join(path, n)
        if os.path.exists(p): sh(f'icacls "{p}" /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F', 20)
def use_data_drive():
    """Make the agent's data folder and Sunshine's config live on DATA_DRIVE. Safe to run again (finished moves are skipped). -> (ok, message)"""
    if os.name != "nt" or not DATA_DRIVE: return True, "Data stays on the system drive"
    drv = DATA_DRIVE.rstrip("\\"); root = drv + "\\"
    if drv.upper() == os.environ.get("SystemDrive", "C:").upper(): return True, "The data drive is the system drive"
    if not os.path.isdir(root) or ctypes.windll.kernel32.GetDriveTypeW(root) != 3: return False, f"{drv} is not a fixed drive on this PC. Set WOL_DATA_DRIVE to another drive letter."
    if shutil.disk_usage(root).free < 1 << 30: return False, f"{drv} has less than 1 GB free."
    sh("schtasks /end /tn WoLHostAgent", 20); sh(f"net stop {SUN_SVC}", 30); sh("taskkill /f /im sunshine.exe", 20); time.sleep(2)      # nothing may hold files open while they move; the later setup steps start both again
    base, notes = os.path.join(root, "WoLData"), []
    def move(src, dst):
        for _ in range(3):                                                                         # a file may still be closing: end the agent again and retry
            ok, m = relocate(src, dst)
            if ok or "in use" not in m: break
            sh("schtasks /end /tn WoLHostAgent", 20); time.sleep(5)
        return ok, (m if ok or "in use" not in m else m.split(". Close")[0] + ". " + move_at_boot())
    ok, m = move(APPDIR, os.path.join(base, "WoLHost"))
    if not ok: return False, m
    relock_appdir(APPDIR); notes.append(m)
    if os.path.isdir(SUN_DIR):
        dst = os.path.join(base, "SunshineConfig"); ok, m = move(os.path.join(SUN_DIR, "config"), dst)
        if not ok: return False, m
        sh(f'icacls "{dst}" /grant *S-1-5-32-545:(OI)(CI)M /T', 60); notes.append(m)             # signed-in users save Sunshine's settings / paired devices there
        note = repair_sun_state()                                                                  # Sunshine is stopped: an empty / damaged state file is set aside now, so it starts clean
        if note: notes.append(note)
    return True, " | ".join(notes)
def move_at_boot():
    """The move could not finish because programs hold files open: run it once at the next start of Windows, before anything is running. -> text for the user"""
    cmd = f'"{sys.executable}" --move-data' if getattr(sys, "frozen", False) else f'"{sys.executable}" "{os.path.abspath(__file__)}" --move-data'
    rc, out = sh(f'schtasks /create /tn WoLHostMoveData /tr "{cmd.replace(chr(34), chr(92) + chr(34))}" /sc onstart /ru SYSTEM /rl HIGHEST /f', 30)
    return "Restart Windows: the move then finishes by itself before anything starts, and the agent comes back on its own." if rc == 0 else f"Close WoL Host, then run as administrator: python wol_host.py --move-data ({out[:80]})"
def step_install(tok):
    ok, note = use_data_drive(); log(f"data drive: {ok} {note}")
    if not ok: return False, note
    if os.path.exists(tsexe()) or shutil.which("tailscale"): return True, "Already installed"
    sh("winget install -e --id Tailscale.Tailscale --silent --accept-source-agreements --accept-package-agreements", 600)
    return (os.path.exists(tsexe()), "Installed" if os.path.exists(tsexe()) else "Install failed - get it from tailscale.com/download")
RELAY = os.path.join(APPDIR, "relay.json")                    # {"ip": phone's Tailscale IP}: the phone whose Tailscale account this PC joined
def relay_ip():
    try:
        with open(RELAY, encoding="utf-8") as f: return str((json.load(f) or {}).get("ip") or "")
    except Exception: return ""
def relay_linked():
    """True when this PC is on the Tailscale account of the WoL Relay phone it was set up with (that phone is visible as a peer). A PC logged in to its own
    Tailscale account is NOT linked."""
    ip = relay_ip()
    return bool(ip) and bool(ts_ip()) and ip in ts_peers()
def parse_relay_token(tok):
    """Phone token = "<tailscale auth key>~<secret>~<phone tailscale ip>". -> (key, phone_ip) or ("", "")"""
    p = (tok or "").strip().split("~")
    if len(p) < 3 or not p[0].startswith("tskey-") or not p[2].strip().startswith("100."): return "", ""
    return p[0], p[2].strip()
def step_join(tok):
    """The PC never uses a Tailscale login of its own: it must join the phone's Tailscale account with a token from the WoL Relay app."""
    key, rip = parse_relay_token(tok)
    if not key:
        if relay_linked(): ensure_unattended(); return True, f"Connected - linked to the phone's Tailscale account ({ts_label() or ts_ip()}, {ts_ip()})"
        if (tok or "").strip(): return False, "That is not a valid token. Generate a new PC token in the WoL Relay phone app and paste all of it."
        return False, "Paste the PC token from the WoL Relay phone app. This PC has to join the phone's Tailscale account (its own Tailscale login is not used)."
    sh(f'"{tsexe()}" up --auth-key={key} --force-reauth --reset --unattended', 120)
    for n in range(10):                                           # the phone must show up in this PC's network, otherwise the PC joined some other account
        _cache.pop("peers", None)
        if ts_ip() and rip in ts_peers(): break
        time.sleep(1.5)
    else:
        return False, "Could not join the phone's Tailscale account (token expired or already used, or the phone is not connected to Tailscale). Generate a new token on the phone."
    try:
        os.makedirs(APPDIR, exist_ok=True)
        with open(RELAY, "w", encoding="utf-8") as f: json.dump({"ip": rip}, f)
        sec = (tok.strip().split("~") + ["", ""])[1]
        if len(sec) >= 16: _write_private(RELAYSEC, json.dumps({"secret": sec}))          # this token is the link to the phone: nothing more to paste in the Remote PIN tab
    except Exception as e: log(f"relay.json: {e!r}")
    ensure_unattended()
    mok, mmsg = send_host_macs()                                                           # first request with this token: it also makes the phone treat this PC as the host
    threading.Thread(target=lambda: access_sync(True), daemon=True).start()               # the phone gets the account PINs right away
    _cache.pop("acct", None)
    return True, f"Connected - joined the phone's Tailscale account ({ts_label() or 'no name'}, {ts_ip()}) · " + (f"sent to the phone: {mmsg}" if mok else f"MAC address NOT sent to the phone ({mmsg}) - press Set up again")
DEF_USER = DEF_PW = "1122"                                           # the login setup uses until you change it on the This PC page
def sun_login():
    """The Sunshine web/API login in use: the one saved by this program, else the default."""
    return sun_creds() or (DEF_USER, DEF_PW)
def check_sun_login(user, pw):
    """Why this username / password cannot be used, or None if it is fine."""
    if not user or not pw: return "Enter both a username and a password."
    if len(user) > 64 or len(pw) > 64: return "Keep the username and the password under 64 characters."
    if user != user.strip() or pw != pw.strip(): return "No spaces at the start or the end, please."
    if re.search(r'["\x00-\x1f]', user + pw): return "Quotes and control characters cannot be used."
    return None
def login_ok(t=None):
    t = tuple(t) if t else sun_login()
    try: return sun_creds() == t and sun_up() and sun_api("/api/config", creds=t)[0] == 200
    except Exception: return False
SUN_STATE = os.path.join(SUN_DIR, "config", "sunshine_state.json")     # Sunshine keeps its web login AND its paired devices here
def repair_sun_state():
    """Sunshine logs 'sunshine_state.json(1): expected value' and then refuses every API call ('not authorized') when this file is empty, damaged or starts with
    a byte-order mark - and `--creds` cannot fix it. A BOM is stripped (pairings are kept); an unreadable file is set aside as .bad-<time> so Sunshine writes a new one
    (the PCs paired before have to pair again). Sunshine must NOT be running. -> a short note, or '' when the file was fine / absent"""
    try:
        if not os.path.isfile(SUN_STATE): return ""
        raw = open(SUN_STATE, "rb").read()
        if raw.startswith(b"\xef\xbb\xbf"):
            open(SUN_STATE, "wb").write(raw[3:]); log("sunshine_state.json had a byte-order mark: removed it"); return "removed a byte-order mark from Sunshine's state file"
        try:
            if raw.strip(): json.loads(raw.decode("utf-8")); return ""
        except Exception: pass
        bad = f"{SUN_STATE}.bad-{time.strftime('%Y%m%d-%H%M%S')}"; os.replace(SUN_STATE, bad)
        log(f"sunshine_state.json was empty / unreadable ({len(raw)} bytes): moved to {bad}"); return "Sunshine's state file was damaged: it was set aside and a new one is created (PCs have to pair again)"
    except Exception as e: log(f"repair_sun_state: {e!r}"); return ""
def _apply_creds(t):
    """Stop Sunshine, store the login in its config with --creds, and remember it for the agent. -> the program's output"""
    sh(f"net stop {SUN_SVC}", 60); sh("taskkill /f /im sunshine.exe", 20); time.sleep(2)
    repair_sun_state()
    out = ""
    try:
        r = _run([SUN_EXE, "--creds", t[0], t[1]], cwd=SUN_DIR, capture_output=True, text=True, timeout=60); out = (r.stdout + r.stderr).strip()
    except Exception as e: out = repr(e)
    log(f"sunshine --creds (user {t[0]}): {out[:300]}")
    os.makedirs(APPDIR, exist_ok=True)
    with open(CREDS, "w", encoding="utf-8") as f: json.dump({"user": t[0], "pw": t[1]}, f)
    sh(f'icacls "{CREDS}" /inheritance:r /grant:r SYSTEM:F Administrators:F', 20)
    return out
def ensure_login(target=None):
    """Make Sunshine's web/API login (user, password) = `target`, or the saved one, or 1122 / 1122 (stop the service, set it with --creds, restart, verify it really works).
    A new login that Sunshine does not accept is rolled back to the previous one. -> (ok, message)"""
    t = tuple(target) if target else sun_login(); old = sun_creds(); shown = f"{t[0]} / {t[1]}"
    if login_ok(t): return True, f"login already {shown}"
    if not sun_installed(): return False, "Sunshine is not installed"
    out = _apply_creds(t)
    def back(why):
        if old and tuple(old) != t:
            _apply_creds(old)
            if has_session(): sun_start()
            return False, f"{why} - the previous login ({old[0]}) was kept."
        return False, why
    if not has_session(): return True, f"login set to {shown} (Sunshine only runs once a user is signed in, so it is checked then)"
    if not sun_start(): return back("Sunshine did not start inside your session. Run Set up again")
    for _ in range(20):
        try:
            if sun_api("/api/config", creds=t)[0] == 200: return True, f"login set to {shown}"
        except Exception: pass
        time.sleep(1)
    return back(f"Sunshine did not accept {shown} ({out[:120] or 'no output from --creds'})")
def step_sunshine(tok):
    if not sun_installed():
        sh("winget install -e --id LizardByte.Sunshine --silent --accept-source-agreements --accept-package-agreements", 900)
        if not sun_installed(): return False, "Install failed - get Sunshine from github.com/LizardByte/Sunshine/releases, then run setup again"
    ok, note = use_data_drive(); log(f"data drive: {ok} {note}")
    if not ok: return False, note
    sh(f"sc stop {SUN_SVC}", 30); sh(f"sc config {SUN_SVC} start= disabled", 20)                 # the boot service would also stream the sign-in screen
    sh(f'icacls "{SUN_DIR}\\config" /grant *S-1-5-32-545:(OI)(CI)M /T', 60)                        # signed-in users may save Sunshine's settings / paired devices
    rc, out = sun_task()
    if rc != 0: return False, f"Could not create the Sunshine sign-in task: {out[:120]}"
    for c in ['netsh advfirewall firewall delete rule name="WoL Host Sunshine TCP"', 'netsh advfirewall firewall delete rule name="WoL Host Sunshine UDP"',
              'netsh advfirewall firewall add rule name="WoL Host Sunshine TCP" dir=in action=allow protocol=TCP localport=47984,47989,48010 remoteip=100.64.0.0/10',
              'netsh advfirewall firewall add rule name="WoL Host Sunshine UDP" dir=in action=allow protocol=UDP localport=47998-48000,48002 remoteip=100.64.0.0/10']: sh(c, 30)
    ok, msg = ensure_login()
    if not ok: return False, msg
    if not has_session(): return True, "Ready: Sunshine starts when a user signs in and is off at the sign-in screen"
    if not sun_start(): return False, "Sunshine installed but did not start in your session."
    for _ in range(20):
        try:
            if sun_api("/api/config")[0] == 200: return True, "Running in your session; starts whenever any user signs in (off at the sign-in screen); Tailscale-only firewall rules added"
        except Exception: pass
        time.sleep(1)
    return True, "Running, but the pairing login was not confirmed - re-run setup if pairing fails"
def step_wol(tok):
    sh(r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f')
    ps("Get-NetAdapter -Physical | ForEach-Object { Set-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket Enabled -ErrorAction SilentlyContinue }")
    sh("powercfg /change standby-timeout-ac 0")      # never sleep on mains power, so streaming stays reachable
    sh("powercfg /change hibernate-timeout-ac 0")
    sh("sc config Tailscale start= delayed-auto", 20)  # Tailscale service starts at boot, no sign-in needed
    return True, "Done. Also enable Wake-on-LAN in the BIOS/UEFI"
def _onedir():
    """True for a PyInstaller --onedir build (WoL-Host.exe next to its _internal folder). Such a build unpacks NOTHING when it starts, so the background
    processes (agent, TimeGuard engine, widgets, the TimeGuard window) start fast and never fail to extract files at boot."""
    return bool(getattr(sys, "frozen", False)) and os.path.isdir(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "_internal"))
def copy_app_dir(dest_dir):
    """Copies the whole onedir program folder to dest_dir. Files that are already there (same size and date) or in use by the old running copy are skipped.
    -> path of the exe inside dest_dir"""
    src = os.path.dirname(os.path.abspath(sys.executable)); dest_dir = str(dest_dir); os.makedirs(dest_dir, exist_ok=True)
    exe = os.path.join(dest_dir, os.path.basename(sys.executable))
    if os.path.normcase(os.path.abspath(src)) == os.path.normcase(os.path.abspath(dest_dir)): return sys.executable
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src); out = dest_dir if rel == "." else os.path.join(dest_dir, rel); os.makedirs(out, exist_ok=True)
        for f in files:
            a, b = os.path.join(root, f), os.path.join(out, f)
            try:
                if os.path.exists(b) and os.path.getsize(a) == os.path.getsize(b) and abs(os.path.getmtime(a) - os.path.getmtime(b)) < 2: continue
                shutil.copy2(a, b)
            except PermissionError: log(f"copy {f}: in use, kept the old file")
            except OSError as e: log(f"copy {f}: {e!r}")
    return exe
def agent_cmd():
    """Command line the scheduled task runs. Copies the program to C:\\ProgramData\\WoLHost so SYSTEM can always reach it."""
    os.makedirs(APPDIR, exist_ok=True)
    if _onedir():
        try: dest = copy_app_dir(os.path.join(APPDIR, "app"))
        except Exception as e: log(f"copy program folder failed: {e!r}"); dest = sys.executable
        return f'"{dest}" --agent'
    if getattr(sys, "frozen", False):
        dest = os.path.join(APPDIR, "WoL-Host.exe")
        try:
            if os.path.abspath(sys.executable).lower() != dest.lower(): shutil.copy2(sys.executable, dest)
        except Exception as e: log(f"copy exe failed: {e!r}"); dest = sys.executable
        return f'"{dest}" --agent'
    dest = os.path.join(APPDIR, "wol_host.py")
    try: shutil.copy2(os.path.abspath(__file__), dest)
    except Exception as e: log(f"copy script failed: {e!r}"); dest = os.path.abspath(__file__)
    py = sys.executable
    pw = os.path.join(os.path.dirname(py), "pythonw.exe")          # no console window
    if os.path.basename(py).lower() == "python.exe" and os.path.exists(pw): py = pw
    return f'"{py}" "{dest}" --agent'
def start_agent():
    sh("schtasks /end /tn WoLHostAgent", 20); time.sleep(1)
    sh("schtasks /run /tn WoLHostAgent", 20)
    for _ in range(10):
        if agent_up(): return True
        time.sleep(0.5)
    return False
def step_agent(tok):
    if ts_ip(): ensure_unattended()                                  # so the PC stays online at the sign-in screen
    sh("schtasks /end /tn WoLHostAgent", 20); time.sleep(1.5)       # stop the old agent first so its file can be overwritten with this version
    cmd = agent_cmd()
    sh('netsh advfirewall firewall delete rule name="WoL Host Agent"', 20)
    sh('netsh advfirewall firewall add rule name="WoL Host Agent" dir=in action=allow protocol=TCP localport=48998 remoteip=100.64.0.0/10', 20)
    sh('netsh advfirewall firewall delete rule name="WoL Host Web"', 20)
    sh('netsh advfirewall firewall delete rule name="WoL Host Web"', 20)          # the browser sign-in page was removed: close its old port 48997
    rc, out = sh(f'schtasks /create /tn WoLHostAgent /tr "{cmd.replace(chr(34), chr(92) + chr(34))}" /sc onstart /ru SYSTEM /rl HIGHEST /f', 30)
    if rc != 0: return False, out[:140]
    ps("$t = Get-ScheduledTask -TaskName WoLHostAgent; $t.Settings.ExecutionTimeLimit='PT0S'; $t.Settings.DisallowStartIfOnBatteries=$false; "
       "$t.Settings.StopIfGoingOnBatteries=$false; $t.Settings.RestartCount=99; $t.Settings.RestartInterval='PT1M'; Set-ScheduledTask -InputObject $t")
    if start_agent(): return True, "Running, and starts at every boot"
    return False, f"Task created but agent did not start. Log: {log_tail()}"
def join_only(tok, mark=lambda i, state, msg="": None, say=lambda t, kind="": None):
    """The Join button: ONLY joins the phone's Tailscale account with the token (installing Tailscale first when it is missing) and tells the phone this PC's Tailscale IP + physical MAC
    addresses. No Sunshine / Wake-on-LAN / agent step is run (that is what Set up is for). mark(i, state, msg) shows the progress on step i of STEPS. -> (ok, message)"""
    if not (tok or "").strip() and not relay_linked(): return False, "Paste the PC token from the phone app first."
    if not (os.path.exists(tsexe()) or shutil.which("tailscale")):
        mark(0, "work"); say("Installing Tailscale…")
        try: ok, msg = step_install(tok)
        except Exception as e: ok, msg = False, str(e)
        log(f"join: install Tailscale: {ok} {msg}"); mark(0, "ok" if ok else "fail", "" if ok else str(msg)[:600])
        if not ok: return False, f"Install Tailscale: {msg}"
    mark(1, "work"); say("Joining the phone's Tailscale network…")
    try: ok, msg = step_join(tok)
    except Exception as e: ok, msg = False, str(e)
    log(f"join: {ok} {msg}"); mark(1, "ok" if ok else "fail", "" if ok else str(msg)[:600])
    return ok, msg
STEPS = [("Install Tailscale", step_install), ("Join Tailscale network", step_join), ("Install & start Sunshine", step_sunshine),
         ("Allow Wake-on-LAN in Windows", step_wol), ("Start host agent at boot", step_agent)]

# ---------------- GUI (customtkinter is only needed here, never by the agent) ----------------
# ---------------- TimeGuard tab ----------------
# timeguard.py is a PySide6 (Qt) program; this window is WebView2 (or Tk), so they cannot share one process / message loop.
# TimeGuard therefore runs as its own process (--tg-gui --embed) and its window is DOCKED into the TimeGuard tab with the Windows API
# (SetParent). Its engine and countdown widgets are SYSTEM tasks that timeguard.py starts itself (--tg-engine / --tg-agent, see tg_main).
TGINFO = os.path.join(APPDIR, "tg_embed.json")                  # hand-shake file: the TimeGuard process writes its window handle here
TGLOG = os.path.join(APPDIR, "timeguard_gui.log")
def helper_argv(args):
    """Like helper_cmd, but as a list (for Popen)."""
    if getattr(sys, "frozen", False): return [sys.executable] + list(args)
    py = sys.executable; pw = os.path.join(os.path.dirname(py), "pythonw.exe")
    if os.path.basename(py).lower() == "python.exe" and os.path.exists(pw): py = pw
    return [py, os.path.abspath(__file__)] + list(args)
_U = None
def _u32():
    """A private user32 (so argtypes set here cannot disturb other code that uses ctypes.windll.user32)."""
    global _U
    if _U is None:
        from ctypes import wintypes as wt
        u = ctypes.WinDLL("user32")
        u.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        u.IsWindow.argtypes = [wt.HWND]; u.IsIconic.argtypes = [wt.HWND]; u.IsWindowVisible.argtypes = [wt.HWND]
        u.ClientToScreen.argtypes = [wt.HWND, ctypes.POINTER(wt.POINT)]
        u.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
        u.GetWindow.argtypes = [wt.HWND, ctypes.c_uint]; u.GetWindow.restype = wt.HWND
        u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        u.GetWindowDpiAwarenessContext.argtypes = [wt.HWND]; u.GetWindowDpiAwarenessContext.restype = ctypes.c_void_p
        u.GetAwarenessFromDpiAwarenessContext.argtypes = [ctypes.c_void_p]; u.GetAwarenessFromDpiAwarenessContext.restype = ctypes.c_int
        _U = u
    return _U
def find_host_hwnd(title="WoL Host"):
    """Window handle of this program's own top-level window (the one that hosts the tab)."""
    from ctypes import wintypes as wt
    u, found = _u32(), []
    cb_t = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    u.EnumWindows.argtypes = [cb_t, wt.LPARAM]
    def cb(h, _):
        pid = wt.DWORD(); u.GetWindowThreadProcessId(h, ctypes.byref(pid))
        if pid.value == os.getpid() and u.IsWindowVisible(h) and not u.GetWindow(h, 4):         # 4 = GW_OWNER: top-level, not owned
            buf = ctypes.create_unicode_buffer(256); u.GetWindowTextW(h, buf, 256)
            if buf.value == title: found.append(h)
        return True
    u.EnumWindows(cb_t(cb), 0)
    return found[0] if found else 0
def dpi_awareness(hwnd):
    """0 unaware, 1 system aware, 2 per-monitor aware (the mode the host window runs in); -1 unknown."""
    try: return int(_u32().GetAwarenessFromDpiAwarenessContext(_u32().GetWindowDpiAwarenessContext(hwnd)))
    except Exception: return -1

def dpi_context(hwnd):
    """The EXACT DPI awareness context of a window as one of the standard constants (-1 unaware, -2 system, -3 per-monitor, -4 per-monitor v2, -5 unaware+GDI scaled), or None.
    Windows only lets a window become a child of another one when both use compatible contexts - per-monitor v1 and v2 are NOT compatible."""
    try:
        u = _u32(); u.GetWindowDpiAwarenessContext.restype = ctypes.c_void_p
        c = u.GetWindowDpiAwarenessContext(hwnd)
        u.AreDpiAwarenessContextsEqual.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        for k in (-4, -3, -2, -1, -5):
            if u.AreDpiAwarenessContextsEqual(ctypes.c_void_p(c), ctypes.c_void_p(k)): return k
    except Exception as e: log(f"dpi context: {e!r}")
    return None

class TgDock:
    """Runs TimeGuard in its own process and docks its window into a rectangle of the host window.
    parent_fn() -> handle of the window the TimeGuard window becomes a child of; rect = x, y, w, h in that window's client pixels."""
    def __init__(self, parent_fn):
        self.parent_fn, self.proc, self.hwnd, self.mode = parent_fn, None, 0, ""
        self.state, self.msg, self.rect, self.visible = "idle", "", None, False       # state: idle | starting | ready | locked | error
        self._lock = threading.RLock(); self.on_change = lambda: None
    def alive(self): return self.proc is not None and self.proc.poll() is None
    def status(self): return {"state": self.state, "msg": self.msg, "mode": self.mode, "running": self.alive()}
    def _set(self, state, msg=""): self.state, self.msg = state, msg; self.on_change()
    def check(self):
        if os.name != "nt": return "TimeGuard only works on Windows."
        if not getattr(sys, "frozen", False):
            if importlib.util.find_spec("PySide6") is None: return "TimeGuard needs PySide6. Install it with:  pip install PySide6   (for all users, not --user)"
        return ""
    def open(self):
        """Start TimeGuard if it is not running. Returns at once; status() tells how it is going."""
        with self._lock:
            if self.state == "starting": return
            if self.state == "ready" and self.alive(): self.place_now(); return
            self.state, self.msg = "starting", "Starting TimeGuard…"
        self.on_change(); threading.Thread(target=self._start, daemon=True).start()
    def _start(self):
        try:
            bad = self.check()
            if bad: return self._set("error", bad)
            parent = self.parent_fn()
            if not parent: return self._set("error", "Could not find this window to dock TimeGuard into.")
            os.makedirs(APPDIR, exist_ok=True)
            for f in (TGINFO, TGINFO + ".quit"):
                try: os.remove(f)
                except OSError: pass
            env = dict(os.environ); aw = dpi_awareness(parent)
            if aw >= 0: env["QT_QPA_PLATFORM"] = "windows:dpiawareness=%d" % aw        # same DPI mode as this window, or Windows refuses to dock it
            ctx = dpi_context(parent)
            if ctx is not None: env["TG_DPI_CTX"] = str(ctx)                            # the exact context (per-monitor v1 vs v2 matters) - TimeGuard applies it before creating any window
            log(f"timeguard docking into hwnd={parent} dpi awareness={aw} context={ctx}")
            logf = open(TGLOG, "ab")
            self.proc = subprocess.Popen(helper_argv(["--tg-gui", "--embed", str(parent), TGINFO]), env=env, stdout=logf, stderr=logf, **NOWIN)
            self.hwnd, self.mode = 0, ""
            try: _u32().AllowSetForegroundWindow(self.proc.pid)                    # lets its admin-password box come to the front
            except Exception: pass
            self._set("starting", "Starting TimeGuard… (type the admin password if it asks for one)")
            while True:
                d = None
                try: d = json.load(open(TGINFO, encoding="utf-8"))
                except Exception: pass
                if d and d.get("pid") == self.proc.pid:
                    if d.get("error"): return self._set("locked" if d.get("locked") else "error", d["error"])
                    if d.get("hwnd"): self.hwnd, self.mode = int(d["hwnd"]), d.get("mode", ""); break
                if self.proc.poll() is not None:
                    try: tail = open(TGLOG, encoding="utf-8", errors="replace").read().strip().splitlines()[-1]
                    except Exception: tail = ""
                    return self._set("error", "TimeGuard closed before it was ready." + (f"\n{tail}" if tail else f"\nDetails: {TGLOG}"))
                time.sleep(0.15)
            try:                                                                    # trust Windows, not the report: is it really a child of this window?
                u = _u32(); u.GetParent.argtypes = [ctypes.c_void_p]; u.GetParent.restype = ctypes.c_void_p
                if self.mode == "child" and (u.GetParent(self.hwnd) or 0) != parent:
                    log("timeguard reported docked but Windows disagrees - using the follow-the-tab mode"); self.mode = "owner"
            except Exception as e: log(f"timeguard parent check: {e!r}")
            log(f"timeguard docked: mode={self.mode} hwnd={self.hwnd} dpi={aw}")
            self._set("ready"); self.place_now()
            threading.Thread(target=self._watch, daemon=True).start()
        except Exception as e: log(f"timeguard start failed: {e!r}"); self._set("error", str(e))
    def _watch(self):
        last = None
        while self.alive():
            if self.mode == "owner" and self.visible:               # not docked: keep the borderless window on top of the tab while this window moves
                try:
                    from ctypes import wintypes as wt
                    u = _u32(); r = wt.RECT(); par = self.parent_fn(); u.GetWindowRect(par, ctypes.byref(r)); cur = (r.left, r.top, r.right, r.bottom, bool(u.IsIconic(par)))
                    if cur != last: last = cur; self.place_now()
                except Exception: pass
                time.sleep(0.05)
            else: time.sleep(0.4)
        if self.state == "ready": self.hwnd = 0; self._set("error", "TimeGuard was closed. Press Retry to start it again.")
    def page(self, i):                                               # TimeGuard sub-menu: the TimeGuard process polls this file
        try:
            with open(TGINFO + ".page", "w") as f: f.write(str(int(i)))
        except Exception as e: log(f"timeguard page: {e!r}")
    def place(self, x, y, w, h): self.rect, self.visible = (int(x), int(y), int(w), int(h)), True; self.place_now()
    def place_now(self):
        if os.name != "nt" or not self.hwnd or not self.visible or not self.rect: return
        from ctypes import wintypes as wt
        try:
            u = _u32(); x, y, w, h = self.rect
            if self.mode == "owner":
                par = self.parent_fn()
                if u.IsIconic(par): return
                pt = wt.POINT(x, y); u.ClientToScreen(par, ctypes.byref(pt)); x, y = pt.x, pt.y
            u.SetWindowPos(self.hwnd, None, x, y, w, h, 0x40 | 0x10 | 0x4000)            # SHOWWINDOW | NOACTIVATE | ASYNCWINDOWPOS, on top of its siblings
        except Exception as e: log(f"timeguard place failed: {e!r}")
    def hide(self):
        self.visible = False
        if os.name == "nt" and self.hwnd:
            try: _u32().SetWindowPos(self.hwnd, None, 0, 0, 0, 0, 0x4000 | 0x80 | 0x1 | 0x2 | 0x4 | 0x10)   # HIDEWINDOW without moving / activating
            except Exception: pass
    def close(self):
        """Ask TimeGuard to save and quit (it also quits by itself when this window is gone); kill it if it hangs."""
        p = self.proc
        if p is None or p.poll() is not None: return
        self.state = "idle"
        try: open(TGINFO + ".quit", "w").close()
        except OSError: pass
        try: p.wait(8)
        except Exception:
            try: p.terminate()
            except Exception: pass
    def standalone(self):
        """Fallback when docking does not work: TimeGuard in its own window."""
        try: subprocess.Popen(helper_argv(["--tg-gui"]), **NOWIN)
        except Exception as e: log(f"timeguard standalone failed: {e!r}")

def tg_main():
    """The roles of timeguard.py inside this program, so one .exe (or this one script) can be everything:
    --tg-engine (SYSTEM task) and --tg-agent (countdown widget in a user session) are what TimeGuard installs itself; --tg-gui [--embed HWND FILE] is its window."""
    timeguard = load_timeguard()                        # with --tg-engine, loading it already runs the engine and exits (before Qt is imported)
    a = sys.argv
    if "--tg-agent" in a: timeguard.run_agent()
    elif "--tg-idle" in a: timeguard.run_idle()
    elif "--embed" in a: i = a.index("--embed"); timeguard.run_embedded(int(a[i + 1]), a[i + 2])
    elif os.name == "nt" and not timeguard.is_admin(): timeguard.elevate()
    else: timeguard.run_gui()

def run_gui():                                   # classic customtkinter window (fallback, --classic)
    import customtkinter as ctk, webbrowser, traceback
    BG, SIDE, CARD, CARD2, LINE = "#0b0e1a", "#080a14", "#121729", "#1a2038", "#262d4d"
    ACC, ACC_H, OK, OK_H, BAD, WARN, MUTED, GREY = "#6c8cff", "#5578f0", "#22c55e", "#16a34a", "#ef4444", "#f59e0b", "#8b93b5", "#4b5275"
    F, MONO = "Segoe UI", "Consolas"
    ctk.set_appearance_mode("dark"); ctk.set_default_color_theme("blue")

    def card(p, **k): return ctk.CTkFrame(p, fg_color=CARD, corner_radius=18, border_width=1, border_color=LINE, **k)
    def row(p): return ctk.CTkFrame(p, fg_color=CARD2, corner_radius=14, border_width=1, border_color=LINE)
    def btn(p, text, cmd, kind="primary", **k):
        st = {"primary": dict(fg_color=ACC, hover_color=ACC_H, text_color="white"), "ok": dict(fg_color=OK, hover_color=OK_H, text_color="white"),
              "warn": dict(fg_color=WARN, hover_color="#b45309", text_color="white"), "bad": dict(fg_color=BAD, hover_color="#b91c1c", text_color="white"),
              "ghost": dict(fg_color="transparent", hover_color=CARD2, border_width=1, border_color=LINE, text_color="white")}[kind]
        k.setdefault("height", 38); k.setdefault("corner_radius", 12)
        return ctk.CTkButton(p, text=text, command=cmd, font=(F, 13, "bold"), **st, **k)
    def section(p, text):
        f = ctk.CTkFrame(p, fg_color="transparent"); f.pack(fill="x", padx=6, pady=(18, 4))
        ctk.CTkLabel(f, text="●", font=(F, 9), text_color=ACC, width=14).pack(side="left"); ctk.CTkLabel(f, text=text.upper(), font=(F, 11, "bold"), text_color=MUTED).pack(side="left")

    class App(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title("WoL Host"); self.geometry("1040x740"); self.minsize(900, 660); self.configure(fg_color=BG)
            self.tipv = ""; self.busy = False; self.info_busy = False; self.toast_job = None
            side = ctk.CTkFrame(self, width=236, corner_radius=0, fg_color=SIDE); side.pack(side="left", fill="y"); side.pack_propagate(False)
            ctk.CTkLabel(side, text="🖥", font=(F, 26, "bold"), text_color="white", fg_color=ACC, width=56, height=56, corner_radius=18).pack(pady=(34, 0))
            ctk.CTkLabel(side, text="WoL Host", font=(F, 20, "bold")).pack(pady=(12, 0))
            ctk.CTkLabel(side, text="Install on the PC you stream from", font=(F, 11), text_color=MUTED).pack(pady=(0, 28))
            self.nav = {}
            for k, t in [("setup", "⚙     Set up"), ("info", "🖥     This PC"), ("tg", "⏱     TimeGuard")]:
                b = ctk.CTkButton(side, text=t, anchor="w", height=46, corner_radius=12, fg_color="transparent", hover_color=CARD2, text_color=MUTED,
                                  font=(F, 14, "bold"), command=lambda k=k: self.show(k)); b.pack(fill="x", padx=16, pady=3); self.nav[k] = b
            adm = is_admin()
            ctk.CTkLabel(side, text="●  Administrator" if adm else "●  Not administrator", font=(F, 12, "bold"), text_color=OK if adm else BAD,
                         fg_color=CARD, corner_radius=16, height=36).pack(side="bottom", fill="x", padx=16, pady=(0, 22))
            self.tipb = ctk.CTkButton(side, text="Tailscale IP: …", height=36, corner_radius=16, fg_color=CARD, hover_color=CARD2, font=(F, 12, "bold"),
                                      command=self.copy_tip); self.tipb.pack(side="bottom", fill="x", padx=16, pady=(0, 8))
            main = ctk.CTkFrame(self, fg_color="transparent"); main.pack(side="left", fill="both", expand=True, padx=30, pady=24)
            self.toast = ctk.CTkLabel(main, text="Ready", font=(F, 13), anchor="w", justify="left", wraplength=700, fg_color=CARD, corner_radius=14, height=46, padx=18)
            self.toast.pack(side="bottom", fill="x", pady=(14, 0))
            self.pages = {k: ctk.CTkFrame(main, fg_color="transparent") for k in ("setup", "info", "tg")}
            self.build_setup(self.pages["setup"]); self.build_info(self.pages["info"]); self.build_tg(self.pages["tg"])
            self.show("info" if agent_up() else "setup"); self.info(); self.after(10000, self.auto)
            self.protocol("WM_DELETE_WINDOW", self.quit_app)

        # ---- helpers
        def head(self, p, title, sub):
            h = ctk.CTkFrame(p, fg_color="transparent"); h.pack(fill="x")
            left = ctk.CTkFrame(h, fg_color="transparent"); left.pack(side="left")
            ctk.CTkLabel(left, text=title, font=(F, 28, "bold"), anchor="w").pack(anchor="w")
            ctk.CTkLabel(left, text=sub, font=(F, 13), text_color=MUTED, anchor="w", justify="left", wraplength=520).pack(anchor="w", pady=(2, 0))
            return h
        def show(self, k):
            for pg in self.pages.values(): pg.pack_forget()
            self.pages[k].pack(fill="both", expand=True, before=self.toast)
            for n, b in self.nav.items(): b.configure(fg_color=CARD2 if n == k else "transparent", text_color="white" if n == k else MUTED)
            if k == "tg": self.cur = "tg"; self.tg_refresh(); self.tgdock.open(); self.after(150, self.tg_fit)
            else: self.cur = k; self.tgdock.hide()
        def quit_app(self): self.tgdock.close(); self.destroy()
        def say(self, t, col="white"):
            def ui():
                self.toast.configure(text=t, text_color=col)
                if self.toast_job: self.after_cancel(self.toast_job)
                self.toast_job = self.after(20000, lambda: self.toast.configure(text="Ready", text_color="white"))
            self.after(0, ui)
        def copy(self, v, what=""): self.clipboard_clear(); self.clipboard_append(v); self.say(f"Copied {what or v}", OK)
        def copy_tip(self):
            if self.tipv: self.copy(self.tipv, f"Tailscale IP {self.tipv}")
            else: self.say("Not connected to Tailscale yet - run Set up first.", BAD)
        def report_callback_exception(self, exc, val, tb):          # a bug in a button handler must never take the window down
            msg = "".join(traceback.format_exception(exc, val, tb)); log("GUI error: " + msg[-800:]); self.say(f"✖ Unexpected error: {val}", BAD)
        def work(self, fn, *buttons):
            """Run fn in a thread, one job at a time; its buttons are disabled meanwhile and re-enabled whatever happens."""
            if self.busy: return self.say("Another task is still running - please wait.", WARN)
            self.busy = True
            for b in buttons: b.configure(state="disabled")
            def run():
                try: fn()
                except Exception as e: log(f"task error: {e!r}"); self.say(f"✖ {e}", BAD)
                finally:
                    self.busy = False; self.after(0, lambda: [b.configure(state="normal") for b in buttons])
            threading.Thread(target=run, daemon=True).start()

        # ---- Set up page
        def build_setup(self, s):
            self.head(s, "Set up this PC", "One click prepares this PC to be woken and streamed over Tailscale")
            box = card(s); box.pack(fill="x", pady=(16, 12))
            ctk.CTkLabel(box, text="Token from the WoL Relay phone app - required: this PC joins the phone's Tailscale account", font=(F, 12), text_color=MUTED).pack(anchor="w", padx=22, pady=(16, 0))
            self.tok = ctk.CTkEntry(box, placeholder_text="Paste PC token from the phone app", height=44, corner_radius=12, border_width=1, border_color=LINE, fg_color=BG)
            self.tok.pack(fill="x", padx=22, pady=(6, 10))
            self.jbtn = btn(box, "🔗   Join Tailscale network", self.join, "primary", height=44); self.jbtn.pack(fill="x", padx=22, pady=(0, 18))
            lst = card(s); lst.pack(fill="x")
            self.steps = []
            for i, (name, _) in enumerate(STEPS):
                r = row(lst); r.pack(fill="x", padx=14, pady=(14 if i == 0 else 4, 14 if i == len(STEPS) - 1 else 4))
                ic = ctk.CTkLabel(r, text="○", font=(F, 18, "bold"), text_color=GREY, width=34); ic.pack(side="left", padx=(12, 0), pady=12)
                ctk.CTkLabel(r, text=name, font=(F, 14, "bold")).pack(side="left", padx=4)
                c = ctk.CTkLabel(r, text="Pending", fg_color=GREY, text_color="white", corner_radius=10, font=(F, 10, "bold"), height=24, padx=10); c.pack(side="right", padx=14)
                self.steps.append((ic, c))
            self.prog = ctk.CTkProgressBar(s, height=8, corner_radius=4, fg_color=CARD2, progress_color=ACC); self.prog.set(0); self.prog.pack(fill="x", pady=(16, 0))
            self.sbtn = btn(s, "⚙   Set up this PC", self.setup, "ok", height=52); self.sbtn.configure(font=(F, 15, "bold")); self.sbtn.pack(fill="x", pady=(14, 0))
        def mark(self, i, state):
            icon, col, txt = {"pending": ("○", GREY, "Pending"), "work": ("◔", WARN, "Working…"), "ok": ("✔", OK, "Done"), "fail": ("✖", BAD, "Failed")}[state]
            self.after(0, lambda: (self.steps[i][0].configure(text=icon, text_color=col), self.steps[i][1].configure(text=txt, fg_color=col)))
        def setup(self):
            if not is_admin(): return self.say("Run WoL Host as Administrator (right-click → Run as administrator).", BAD)
            tok = self.tok.get().strip()
            for i in range(len(STEPS)): self.mark(i, "pending")
            self.prog.set(0)
            def f():
                fails = 0
                for i, (name, fn) in enumerate(STEPS):
                    self.mark(i, "work"); self.say(f"{name}…")
                    try: ok, msg = fn(tok)
                    except Exception as e: ok, msg = False, str(e)
                    log(f"step {name}: {ok} {msg}"); self.mark(i, "ok" if ok else "fail"); self.after(0, lambda v=(i + 1) / len(STEPS): self.prog.set(v))
                    if not ok: fails += 1; self.say(f"✖ {name}: {msg}", BAD)
                    if not ok and fn is step_join: break                      # nothing else works without the phone's Tailscale account
                self.say("✔ This PC is ready. Add its Tailscale address in the client app." if not fails else f"{fails} step(s) failed - see the message above, then run Set up again.", OK if not fails else WARN)
                self.info()
            self.work(f, self.sbtn, self.jbtn)
        def join(self):
            """Join button: only joins the phone's Tailscale account with the token (no other Set up step)."""
            if not is_admin(): return self.say("Run WoL Host as Administrator (right-click → Run as administrator).", BAD)
            tok = self.tok.get().strip()
            for i in range(len(STEPS)): self.mark(i, "pending")
            self.prog.set(0)
            def f():
                ok, msg = join_only(tok, lambda i, st, m="": self.mark(i, st), lambda t, k="": self.say(t))
                self.say(("✔ " if ok else "✖ ") + str(msg)[:300], OK if ok else BAD)
                if ok: self.after(0, lambda: self.prog.set(1))
                self.info()
            self.work(f, self.sbtn, self.jbtn)

        # ---- This PC page
        def build_info(self, i):
            h = self.head(i, "This PC", "Status of everything the client app needs, in one place")
            self.rbtn = btn(h, "⟳  Refresh", self.info, "ghost", width=112); self.rbtn.pack(side="right", anchor="n")
            body = ctk.CTkScrollableFrame(i, fg_color="transparent"); body.pack(fill="both", expand=True, pady=(10, 0)); self.body = body
            tiles = ctk.CTkFrame(body, fg_color="transparent"); tiles.pack(fill="x", pady=(6, 0)); tiles.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="t")
            self.tv = {}
            for c, t in enumerate(("Tailscale", "Sunshine", "Host agent", "Pairing login")):
                f = card(tiles); f.grid(row=0, column=c, sticky="nsew", padx=5)
                ctk.CTkLabel(f, text=t.upper(), font=(F, 10, "bold"), text_color=MUTED).pack(anchor="w", padx=16, pady=(14, 0))
                v = ctk.CTkLabel(f, text="…", font=(F, 15, "bold"), anchor="w"); v.pack(anchor="w", padx=16, pady=(2, 14)); self.tv[t] = v
            section(body, "PC name (shown in WoL Remote)")
            pnc = card(body); pnc.pack(fill="x", padx=2); pnr = ctk.CTkFrame(pnc, fg_color="transparent"); pnr.pack(fill="x", padx=16, pady=16)
            self.pcname = ctk.CTkEntry(pnr, width=280, height=38); self.pcname.insert(0, pc_label() or socket.gethostname()); self.pcname.pack(side="left")
            btn(pnr, "Save name", self.save_pcname, "primary").pack(side="left", padx=8)
            section(body, "Actions")
            ac = card(body); ac.pack(fill="x", padx=2)
            ar = ctk.CTkFrame(ac, fg_color="transparent"); ar.pack(fill="x", padx=16, pady=16)
            self.abtn = btn(ar, "⬆  UPDATE", self.restart, "warn"); self.abtn.pack(side="left")
            self.rbtn = btn(ar, "🗑  Remove service", self.remove_service, "bad"); self.rbtn.pack(side="left", padx=(8, 0))
            self.sbtn2 = btn(ar, "▶  Start Sunshine", self.start_sun, "ghost"); self.sbtn2.pack(side="left", padx=8)
            btn(ar, "🌐  Open Sunshine web UI", lambda: webbrowser.open(f"https://localhost:{SUN_UI}"), "ghost").pack(side="left")
            section(body, "Sunshine login")
            lg = card(body); lg.pack(fill="x", padx=2)
            self.lg_val = {}
            for k, v in (("Username", sun_login()[0]), ("Password", sun_login()[1])):
                r = row(lg); r.pack(fill="x", padx=14, pady=(14 if k == "Username" else 4, 4))
                ctk.CTkLabel(r, text=k, font=(F, 13), text_color=MUTED, width=150, anchor="w").pack(side="left", padx=16, pady=12)
                self.lg_val[k] = ctk.CTkLabel(r, text=v, font=(MONO, 15, "bold")); self.lg_val[k].pack(side="left")
                btn(r, "Copy", lambda k=k: self.copy(self.lg_val[k].cget("text")), "ghost", width=70, height=30).pack(side="right", padx=12)
            self.lbtn = btn(lg, "✎  Change Sunshine login", self.change_login, "ghost"); self.lbtn.pack(anchor="w", padx=14, pady=(6, 14))
            section(body, "Network")
            self.net = card(body); self.net.pack(fill="x", padx=2, pady=(0, 10))
        def auto(self): self.info(); self.after(10000, self.auto)
        def info(self):
            if self.info_busy: return
            self.info_busy = True
            def f():
                try:
                    sun, inst, ag, tip = sun_up(), sun_installed(), agent_up(), ts_ip()
                    lg = login_ok() if sun else False; wm = physical_macs(); ms = macs()
                    ss = sessions(); who = ", ".join(f"{x['user']} ({x['state']})" for x in ss)
                    tnet = ts_label() if tip else ""
                    rows = [("Computer name", socket.gethostname(), None), ("Tailscale address", tip or "Not connected", "copy" if tip else None)] + \
                           ([("Tailscale account" if "@" in tnet else "Tailscale network", tnet, "copy")] if tnet else []) + [
                            ("Signed-in user", who or "Nobody (sign-in screen)", None)] + \
                           [("MAC (physical)" if m in wm else "MAC (virtual)", m, "copy") for m in ms]
                    def ui():
                        self.tipv = tip; self.tipb.configure(text=f"Tailscale IP: {tip or 'not connected'}")
                        for k, (txt, col) in {"Tailscale": (("● Connected" + (f" · {tnet}" if tnet else "") if relay_linked() else "● Not linked to phone") if tip else "● Offline", OK if tip and relay_linked() else BAD),
                                              "Sunshine": (("● Running" if sun else "● Waiting for sign-in" if inst and not ss else "● Stopped" if inst else "● Not installed"), OK if sun else GREY if inst and not ss else BAD),
                                              "Host agent": ("● Running" if ag else "● Stopped", OK if ag else BAD),
                                              "Pairing login": ((f"● {sun_login()[0]} / {sun_login()[1]}" if lg else "● Needs fix") if sun else "● Sunshine off", OK if lg else WARN if sun else GREY)}.items():
                            self.tv[k].configure(text=txt, text_color=col)
                        for k, v in zip(("Username", "Password"), sun_login()): self.lg_val[k].configure(text=v)
                        for c in self.net.winfo_children(): c.destroy()
                        for n, (k, v, x) in enumerate(rows):
                            r = row(self.net); r.pack(fill="x", padx=14, pady=(14 if n == 0 else 4, 14 if n == len(rows) - 1 else 4))
                            ctk.CTkLabel(r, text=k, font=(F, 13), text_color=MUTED, width=210, anchor="w").pack(side="left", padx=16, pady=12)
                            ctk.CTkLabel(r, text=v, font=(MONO, 14, "bold")).pack(side="left")
                            if x: btn(r, "Copy", lambda v=v: self.copy(v), "ghost", width=70, height=30).pack(side="right", padx=12)
                    self.after(0, ui)
                finally: self.info_busy = False
            threading.Thread(target=f, daemon=True).start()
        def restart(self):
            if not is_admin(): return self.say("Run WoL Host as Administrator.", BAD)
            self.say("Updating the agent, checking the Sunshine login and repairing TimeGuard protection…")
            def f():
                ok, _ = step_agent(None)
                if sun_installed(): sun_task(); sh("taskkill /f /im sunshine.exe", 20); time.sleep(1)      # re-create the hidden launcher, restart Sunshine through it
                lg, lm = ensure_login() if sun_installed() else (False, "Sunshine is not installed - run Set up")
                self.say("Repairing TimeGuard protection…"); tok, tmsg = tg_repair()
                if not lg: self.say(f"✖ {lm}", BAD)
                elif not ok: self.say(f"✖ Agent did not start. Log: {log_tail()}", BAD)
                elif not tok: self.say(f"✔ Agent updated and running · ✖ {tmsg}", WARN)
                else: self.say(f"✔ Agent updated and running · Sunshine login is {sun_login()[0]} / {sun_login()[1]} · {tmsg}", OK)
                self.info()
            self.work(f, self.abtn)
        def save_pcname(self):
            if not is_admin(): return self.say("Run WoL Host as Administrator.", BAD)
            try: n = set_pc_label(self.pcname.get())
            except Exception as e: return self.say(f"✖ Could not save the name: {e}", BAD)
            self.say(f"✔ This PC is now called “{n}” in WoL Remote." if n else "✔ Name cleared.", OK)
        def remove_service(self):
            if not is_admin(): return self.say("Run WoL Host as Administrator.", BAD)
            import tkinter.messagebox as mb
            if not mb.askyesno("Remove service", "Remove the services?\n\n- TimeGuard: time limits stop being enforced and the countdown widgets close.\n- WoL Host agent: this PC can no longer be woken, signed in or controlled remotely until you press UPDATE again."): return
            def f():
                ok, msg = remove_all_services(); self.say(("✔ " if ok else "✖ ") + msg, OK if ok else BAD); self.info()
            self.work(f, self.rbtn)
        def change_login(self):
            """Ask for a new Sunshine username and password and apply them."""
            if not is_admin(): return self.say("Run WoL Host as Administrator.", BAD)
            u0 = sun_login()[0]
            user = ctk.CTkInputDialog(text=f"New Sunshine username (now: {u0}):", title="Sunshine login").get_input()
            if not user: return
            pw = ctk.CTkInputDialog(text="New Sunshine password:", title="Sunshine login").get_input()
            if not pw: return
            bad = check_sun_login(user.strip(), pw)
            if bad: return self.say(f"✖ {bad}", BAD)
            self.say("Changing the Sunshine login…")
            def f():
                ok, msg = ensure_login((user.strip(), pw)) if sun_installed() else (False, "Sunshine is not installed - run Set up")
                self.say(f"✔ {msg}" if ok else f"✖ {msg}", OK if ok else BAD); self.info()
            self.work(f, self.lbtn)
        def start_sun(self):
            if not is_admin(): return self.say("Run WoL Host as Administrator.", BAD)
            def f():
                ok = sun_start() if sun_installed() else False
                self.say("✔ Sunshine is running." if ok else "Nobody is signed in: Sunshine only runs inside a signed-in session, by design." if sun_installed() and not has_session() else "✖ Sunshine did not start (is it installed? run Set up).", OK if ok else WARN); self.info()
            self.work(f, self.sbtn2)

        # ---- TimeGuard page (the TimeGuard window is docked into the frame below)
        def build_tg(self, p):
            import tkinter as tk
            self.head(p, "TimeGuard", "Screen-time limits for the Windows accounts on this PC - TimeGuard runs inside this tab")
            self.tgstage = tk.Frame(p, bg=CARD, highlightthickness=1, highlightbackground=LINE); self.tgstage.pack(fill="both", expand=True, pady=(16, 0))
            self.tgmsg = ctk.CTkLabel(self.tgstage, text="", font=(F, 14), text_color=MUTED, wraplength=560, justify="center", fg_color=CARD)
            self.tgbtns = ctk.CTkFrame(self.tgstage, fg_color=CARD)
            btn(self.tgbtns, "⟳  Retry", lambda: self.tgdock.open(), "primary", width=120).pack(side="left", padx=6)
            self.tgalone = btn(self.tgbtns, "Open in its own window", lambda: self.tgdock.standalone(), "ghost", width=190); self.tgalone.pack(side="left", padx=6)
            self.cur = ""; self.tgdock = TgDock(lambda: self.tgstage.winfo_id()); self.tgdock.on_change = lambda: self.after(0, self.tg_refresh)
            self.tgstage.bind("<Configure>", lambda e: self.tg_fit())
        def tg_fit(self):
            if self.cur == "tg" and self.tgstage.winfo_width() > 60: self.tgdock.place(0, 0, self.tgstage.winfo_width(), self.tgstage.winfo_height())
        def tg_refresh(self):
            d = self.tgdock.status(); self.tgmsg.place_forget(); self.tgbtns.place_forget()
            if d["state"] == "ready": return
            bad = d["state"] in ("error", "locked")
            self.tgmsg.configure(text=("⏱  Starting TimeGuard…" if not bad else "") + (("\n\n" if not bad else "") + d["msg"] if d["msg"] else "")); self.tgmsg.place(relx=0.5, rely=0.42, anchor="center")
            if bad: self.tgbtns.place(relx=0.5, rely=0.62, anchor="center")
    try: App().mainloop()
    except Exception:
        tb = traceback.format_exc(); log("GUI failed to start: " + tb[-800:])
        try:
            import tkinter.messagebox as mb; mb.showerror("WoL Host failed to start", tb[-1500:])
        except Exception: pass
        raise

HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>WoL Host</title><meta name="viewport" content="width=device-width,initial-scale=1">
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
.nav button .chev{margin-left:auto;display:grid;place-items:center;transition:transform .2s var(--ease)}.nav button.exp .chev{transform:rotate(180deg)}
.subnav{display:flex;flex-direction:column;gap:3px;overflow:hidden;max-height:0;transition:max-height .22s var(--ease)}.subnav.open{max-height:220px}.subnav:not(.open)>button{visibility:hidden}
.nav .subnav button{padding:8px 14px 8px 44px;font-size:13px;font-weight:600;justify-content:space-between;border-radius:10px}
.nav .subnav button.on{background:rgba(108,140,255,.10);color:#fff}.nav .subnav button.on::before{display:none}
.nav .subnav button em{font-style:normal;font-size:10.5px;font-weight:700;color:#fff;background:var(--acc);border-radius:999px;padding:1px 7px}.nav .subnav button em:empty{display:none}
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
.row.hl-bad{box-shadow:inset 0 0 0 1.5px var(--bad)}.sec-row{display:flex;align-items:flex-end;justify-content:space-between}.sec-row .btn{margin-bottom:6px}
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
main.tgmode{overflow:hidden;padding:24px 28px 64px}
.page[data-k=tg].on{display:flex;flex-direction:column;height:100%;max-width:none;margin:0}
.tgstage{flex:1;min-height:300px;display:flex;flex-direction:column;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:var(--r);background:var(--surf);overflow:hidden}
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
chev:'<path d="m6 9 6 6 6-6"/>',
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
async function copy(t,what){let ok=false;try{if(window.pywebview&&pywebview.api&&pywebview.api.copy_text)ok=(await pywebview.api.copy_text(String(t)))===true}catch(e){}if(!ok){try{await navigator.clipboard.writeText(t);ok=true}catch(e){}}if(!ok){try{const a=document.createElement('textarea');a.value=t;a.style.cssText='position:fixed;left:0;top:0;opacity:0';document.body.append(a);a.focus();a.select();ok=document.execCommand('copy');a.remove()}catch(e){}}toast(ok?'Copied '+(what||t):'Could not copy - select the text and press Ctrl+C',ok?'ok':'bad')}
// ---- GPU check: proves the page is really composited on the graphics card
function gpuInfo(){try{const c=document.createElement('canvas'),gl=c.getContext('webgl2')||c.getContext('webgl');if(!gl)return{hw:false,name:'WebGL unavailable'};const x=gl.getExtension('WEBGL_debug_renderer_info'),n=String(x?gl.getParameter(x.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER));
  return{hw:!/swiftshader|llvmpipe|software|basic render|microsoft basic|softpipe/i.test(n),name:n.replace(/^ANGLE \((.*)\)$/,'$1').replace(/,? ?Direct3D\S*.*$/,'').replace(/^[^,]+, /,'')}}catch(e){return{hw:false,name:'unknown'}}}
// ---- app shell
let S=null,M=null,CUR=null,PAGES={};
function shell(o){
  const nav=h('div',{class:'nav'}),main=h('main',{});const bn=h('div',{class:'banner'},'Lost connection to the app - close and reopen it.');main.append(bn);
  o.nav.forEach(([k,label,icon])=>{const sb=o.subs&&o.subs[k];const b=h('button',{type:'button','data-k':k,onclick:()=>sb?toggleSub(k):go(k)},ic(icon,18),h('span',{},label),sb?h('i',{class:'chev'},ic('chev',14)):null);nav.append(b);if(sb){const box=h('div',{class:'subnav','data-sub':k},sb.map(([i,l])=>h('button',{type:'button','data-i':i,onclick:()=>subGo(k,i)},h('span',{},l),h('em',{})))); nav.append(box); box.querySelector('button').classList.add('on')}const el=h('section',{class:'page','data-k':k});main.append(el);PAGES[k]={el,...o.pages[k](el)}});
  const g=gpuInfo(),gp=h('div',{class:'chip c-'+(g.hw?'ok':'warn'),title:g.hw?'The interface is drawn by your graphics card ('+g.name+')':'Software rendering. Start without --software-ui for GPU drawing.'},h('span',{class:'dot'}),h('span',{},g.hw?'GPU accelerated':'Software rendering'));
  const foot=h('div',{class:'sfoot'},o.foot||[],gp);
  $('#app').append(h('aside',{class:'side'},h('div',{class:'brand'},h('div',{class:'mark'},ic(o.icon,22)),h('div',{},h('b',{},o.title),h('small',{},o.sub))),nav,foot),main);
  window.__nav=nav;window.__banner=bn;return{foot,main}}
function toggleSub(k){const box=document.querySelector('.subnav[data-sub="'+k+'"]'),btn=__nav.querySelector('button[data-k="'+k+'"]');
  if(CUR!==k){go(k);box.classList.add('open');btn.classList.add('exp');return}
  const o=box.classList.toggle('open');btn.classList.toggle('exp',o)}
function subGo(k,i){if(CUR!==k)go(k);__nav.querySelectorAll('.subnav[data-sub="'+k+'"] button').forEach(b=>b.classList.toggle('on',b.dataset.i===String(i)));api('tg_page',+i);
  [0,150].forEach(t=>setTimeout(()=>{const p=PAGES[k];p&&p.place&&p.place()},t))}
function go(k){const prev=CUR;CUR=k;if(prev&&prev!==k&&PAGES[prev]&&PAGES[prev].leave)PAGES[prev].leave();$('main').classList.toggle('tgmode',k==='tg');for(const[n,p]of Object.entries(PAGES))p.el.classList.toggle('on',n===k);__nav.querySelectorAll('.nav>button').forEach(b=>b.classList.toggle('on',b.dataset.k===k));api('page',k);const p=PAGES[k];if(p.enter)p.enter();renderCur();$('main').scrollTop=0}
function renderCur(){if(!S||!CUR)return;const p=PAGES[CUR];if(p.render)p.render(S);if(window.__side)window.__side(S)}
async function run(o){
  await READY;M=await window.pywebview.api.meta();const sh=shell(o);window.__foot=sh.foot;o.start&&o.start();go(o.first());
  let rev=0,lastToast=0,lastGo=0,bad=0;
  for(;;){try{const s=await window.pywebview.api.poll(rev);bad=0;__banner.classList.remove('on');
      if(s){rev=s.rev;S=s;if(s.toast&&s.toast.id!==lastToast){const first=!lastToast;lastToast=s.toast.id;if(!first||s.toast.t!=='Ready')toast(s.toast.t,s.toast.c)}
        if(s.go&&s.go.id!==lastGo){lastGo=s.go.id;go(s.go.page)}else renderCur()}}
    catch(e){if(++bad>4)__banner.classList.add('on')}
    await sleep(450)}}

const head=(t,s,...a)=>h('div',{class:'head'},h('div',{},h('h1',{},t),h('p',{},s)),h('div',{class:'sp'}),...a);
const PG={};
const KIND={ok:'ok',bad:'bad',warn:'warn',mut:'mut'};
const tsChip=h('div',{class:'chip c-mut',style:'max-width:100%;margin-top:12px'},h('span',{class:'dot'}),h('span',{style:'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0'},'Tailscale: checking…'));
PG.setup=el=>{
  const tok=h('input',{class:'in mono',placeholder:'Paste PC token from the phone app',spellcheck:false}),list=h('div',{class:'list'}),bar=h('i'),
    go_=btn('Set up this PC','ok lg',()=>api('setup',tok.value),{icon:'wrench',size:18}),
    joinb=btn('Join Tailscale network','primary lg',()=>api('join',tok.value),{icon:'wifi',size:18});
  el.append(head('Set up this PC','One click prepares this PC to be woken and streamed over Tailscale'),
    h('div',{class:'card'},h('label',{class:'f'},'Token from the WoL Relay phone app - required: this PC joins the phone’s Tailscale account'),tok,h('div',{style:'height:12px'}),joinb,tsChip,h('div',{class:'sub',style:'margin:8px 0 0'},'Join only connects this PC to the phone’s Tailscale network and sends the phone its Tailscale IP and MAC addresses. Set up below does everything else.')),
    h('div',{class:'card flush'},list),h('div',{class:'progress'},bar),h('div',{style:'height:12px'}),go_);
  return{render(S){go_.disabled=joinb.disabled=S.busy;go_.classList.toggle('busy',S.busy);bar.style.transform='scaleX('+S.prog+')';
    if(!sig(list,S.steps))return;
    list.replaceChildren(...S.steps.map(s=>{const[c,t]={pending:['mut','Pending'],work:['warn','Working…'],ok:['ok','Done'],fail:['bad','Failed']}[s.state];
      return h('div',{class:'row'},h('div',{class:'av',style:'width:38px;height:38px;border-radius:50%;color:var(--'+(c==='mut'?'dim':c)+')'},s.state==='work'?h('span',{class:'btn busy',style:'height:16px;padding:0;pointer-events:none'}):ic(s.state==='ok'?'check':s.state==='fail'?'x':'cpu',18)),
        h('div',{class:'grow'},h('div',{class:'t'},s.name),s.state==='fail'&&s.msg?h('div',{class:'m',style:'white-space:pre-wrap;word-break:break-word;color:var(--bad)'},s.msg):null),h('span',{class:'pill c-'+c},t))}))}}};
PG.info=el=>{
  const pcn=h('input',{class:'in',placeholder:'e.g. Gaming PC',style:'max-width:320px'});
  const tiles=h('div',{class:'tiles'}),net=h('div',{class:'list'}),sun=h('div',{class:'list'});
  const ab=btn('UPDATE','warn',()=>api('restart'),{icon:'upload'}),rb=btn('Remove service','danger',async()=>{if(await confirmBox('Remove the services?','TimeGuard stops enforcing limits and its countdown widgets close. The WoL Host agent is turned off too, so this PC can no longer be signed in or controlled remotely until you press UPDATE again.','Remove'))api('remove_tg')},{icon:'trash'}),sb=btn('Start Sunshine','ghost',()=>api('start_sun'),{icon:'play',size:14});
  const lgl=h('div',{class:'list'});
  const editLg=async()=>{const[u0,p0]=(S&&S.login)||[M.def_user,M.def_pw],ui=h('input',{class:'in mono',value:u0,spellcheck:false,autocomplete:'off'}),pi=h('input',{class:'in mono',value:p0,spellcheck:false,autocomplete:'off'});
    const r=await modal({title:'Change Sunshine login',text:'The username and password of Sunshine’s own web page. This program uses them to enter pairing PINs, so the new login is set in Sunshine and saved here together.',body:[field('Username',ui),h('div',{style:'height:10px'}),field('Password',pi)],ok:'Save',
      onok:()=>{if(!ui.value.trim()){ui.focus();return false}if(!pi.value){pi.focus();return false}return{u:ui.value.trim(),p:pi.value}}});
    if(r)api('set_sun_login',r.u,r.p)};
  const eb=btn('Change Sunshine login','ghost',editLg,{icon:'key',size:14});
  const kv=(k,v,cp,w)=>h('div',{class:'kv'},h('span',{style:w?'width:'+w:''},k),h('code',{class:'tsel'},v),cp?btn('Copy','ghost',()=>copy(v),{icon:'copy',cls:'sm',size:14}):null);
  el.append(head('This PC','Status of everything the client app needs, in one place',btn('Refresh','ghost',()=>api('refresh'),{icon:'refresh'})),tiles,
    section('Actions'),h('div',{class:'card'},h('div',{class:'hbar'},ab,rb,sb,btn('Open Sunshine web UI','ghost',()=>api('open_sun_ui'),{icon:'globe'}),eb)),
    section('PC name'),h('div',{class:'card'},h('div',{class:'sub',style:'margin:0 0 10px'},'The name WoL Remote shows for this PC. It is set here only - the client app cannot rename it.'),h('div',{class:'hbar'},pcn,btn('Save name','primary',async()=>{const r=await api('set_pcname',pcn.value);if(r!=null)pcn.value=r},{icon:'check'}))),
    section('Sunshine login'),lgl,
    section('Network'),net);
  lgl.replaceChildren(kv('Username',M.def_user,true),kv('Password',M.def_pw,true));
  return{enter(){api('get_pcname').then(v=>{if(v!=null&&document.activeElement!==pcn)pcn.value=v})},render(S){ab.disabled=sb.disabled=eb.disabled=S.busy;
    if(S.login&&sig(lgl,S.login))lgl.replaceChildren(kv('Username',S.login[0],true),kv('Password',S.login[1],true));
    if(sig(tiles,S.tiles))tiles.replaceChildren(...S.tiles.map(([k,t,c])=>h('div',{class:'tile'},h('small',{},k),h('b',{class:'c-'+c},h('span',{class:'dot'+(c==='ok'?' live':'')}),t))));
    if(sig(net,S.rows))net.replaceChildren(...(S.rows.length?S.rows.map(([k,v,cp])=>kv(k,v,cp,'210px')):[empty('monitor','Loading…','Reading this PC’s status.')]))}}};
PG.pin=el=>{
  const fmtT=t=>new Date(t*1000).toLocaleString();
  const pinList=h('div',{class:'list'}),aS=h('div',{class:'sub'}),aPh=h('div',{class:'sub',style:'margin-top:6px'});
  // ---- status: do wake / stream ask for a PIN, and does the phone have the PINs?
  const loadAccess=async()=>{const A=await api('access_state')||{},P=A.phone||{};
    aS.replaceChildren(A.required?('Waking and streaming ask for a PIN: the PIN of any of the '+A.count+' account'+(A.count===1?'':'s')+' that '+(A.count===1?'has':'have')+' one.'):'No account has a PIN yet, so waking and streaming ask for none. Set a PIN for an account below.');
    aPh.replaceChildren(P.linked?('Phone '+P.ip+' (linked when this PC was set up): '+(P.ok?'has the PINs'+(P.t?' (checked '+new Date(P.t*1000).toLocaleTimeString()+')':''):(P.msg||'not synced yet, trying again'))):'This PC is not linked to a WoL Relay phone, so the phone cannot ask for the PINs. Run Set up again with a PC token from the phone app - that is what links it, there is nothing to paste here. '+(P.msg||''))};
  // ---- one PIN per Windows account: it signs the account in / out AND is the PIN for wake and stream
  const loadPins=async()=>{const L=await api('pin_state')||[];
    pinList.replaceChildren(...(L.length?L.map(a=>{
      const i=h('input',{class:'in',type:'password',inputmode:'numeric',maxlength:32,autocomplete:'off',placeholder:a.set?'New PIN (4-32 digits)':'PIN (4-32 digits)',style:'width:170px'}),
        n=h('input',{class:'in',type:'number',min:1,max:3650,value:'30',style:'width:76px;display:none'}),
        u=select(['permanent','days','weeks','months'],'permanent',v=>{n.style.display=v==='permanent'?'none':''},'sm');
      const save=async()=>{const v=i.value;if(!/^\d{4,32}$/.test(v)){i.focus();return toast('A PIN is 4 to 32 digits (numbers only).','bad')}
        const perm=u.value==='permanent',k=parseInt(n.value,10);if(!perm&&!(k>=1&&k<=3650)){n.focus();return toast('Enter how long the PIN lasts (1 to 3650).','bad')}
        const r=await api('pin_set',a.user,v,perm?0:k,u.value)||{};i.value='';toast(r.msg||'Could not set the PIN',r.ok?(r.warn?'warn':'ok'):'bad');loadPins();loadAccess()};
      i.addEventListener('keydown',e=>{if(e.key==='Enter')save()});
      const how=a.set?(a.dual?'The PIN alone signs this account out. Signing it in needs the PIN and the '+(a.msa?'Microsoft account':'Windows')+' password.':'No Windows password: this PIN alone signs it in and out.')+' It is also the PIN for waking and streaming as '+a.user+'.'+(a.exp?' Expires '+fmtT(a.exp)+' and is then removed automatically.':' It never expires.'):'No PIN - set one so the client app can wake and stream as this account, and sign it out (or in, once its password is removed).';
      return h('div',{class:'row'},avatar('shield'),h('div',{class:'grow'},h('div',{class:'t'},a.user,pill(a.set?(a.dual?'PIN + password':'PIN set'):'No PIN',a.set?'ok':'mut'),a.msa?pill('Microsoft account','mut'):null),h('div',{class:'m'},how)),
        h('div',{class:'acts'},i,h('b',{},'lasts'),u,n,btn(a.set?'Change':'Set PIN','primary',save,{cls:'sm'}),
          a.set?btn('Remove','danger',async()=>{const r=await api('pin_clear',a.user)||{};toast(r.msg||'Failed',r.ok?(r.warn?'warn':'ok'):'bad');loadPins();loadAccess()},{cls:'sm'}):null))}):[h('div',{class:'sub'},'No Windows accounts found yet.')]))};
  const aSync=btn('Sync now','ghost',async()=>{const r=await api('access_sync_now')||{};toast(r.msg||'Failed',r.ok?'ok':'bad');loadAccess()},{icon:'refresh',cls:'sm'});
  setInterval(()=>{if(CUR==='pin')loadAccess()},5000);
  el.append(head('Remote PIN','One PIN per Windows account - it signs the account in and out, and is also the PIN for waking and streaming as it',btn('Reload','ghost',()=>{loadPins();loadAccess()},{icon:'refresh'})),
    // the "Waking and streaming" section (status text + Sync now) is hidden on purpose; aS / aPh / aSync still exist so loadAccess() keeps working
    section('Windows account PINs'),
    h('div',{class:'card'},h('div',{class:'sub'},'Set a PIN for each account WoL Remote may use. Accounts with NO Windows password: this PIN alone signs them in and out. Accounts that keep a password (administrators, Microsoft accounts): this PIN alone signs them out, and signing them in needs this PIN and their password. Choose "lasts" to make a PIN expire by itself (then that account can no longer be woken, streamed or signed in remotely until you set a new one).'),pinList));
  return{enter(){loadPins();loadAccess()}}};
PG.tg=el=>{
  const stage=h('div',{class:'tgstage'});
  el.append(head('TimeGuard','Screen-time limits for the Windows accounts on this PC - TimeGuard runs inside this tab'),stage);
  const place=()=>{if(CUR!=='tg')return;const r=stage.getBoundingClientRect(),d=window.__QT?1:(window.devicePixelRatio||1);if(r.width<60||r.height<60)return;
    api('tg_place',Math.round(r.left*d),Math.round(r.top*d),Math.round(r.width*d),Math.round(r.height*d))};
  new ResizeObserver(place).observe(stage);window.addEventListener('resize',place);
  return{place,enter(){api('tg_open');[0,120,400].forEach(t=>setTimeout(place,t))},leave(){api('tg_hide')},
    render(S){const t=S.tg||{state:'idle',msg:''};const rq=__nav.querySelector('.subnav button[data-i="2"] em');if(rq)rq.textContent=t.pending?String(t.pending):'';if(!sig(stage,t))return;
      if(t.state==='ready'){stage.replaceChildren();return}
      const bad=t.state==='error'||t.state==='locked';
      stage.replaceChildren(empty(bad?'shield':'refresh',t.state==='locked'?'TimeGuard is locked':bad?'TimeGuard could not start':'Starting TimeGuard…',t.msg||''),
        bad?h('div',{class:'hbar'},btn(t.state==='locked'?'Unlock':'Retry','primary',()=>api('tg_open'),{icon:'refresh'}),t.running?null:btn('Open in its own window','ghost',()=>api('tg_window'),{icon:'monitor'})):null)}}};
const tipChip=h('div',{class:'chip click c-mut',title:'Copy the Tailscale address',onclick:()=>S&&S.tip?copy(S.tip,'Tailscale IP '+S.tip):toast('Not connected to Tailscale yet - run Set up first.','bad')},h('span',{class:'dot'}),h('span',{},'Tailscale IP: …'));
const admChip=h('div',{class:'chip c-mut'},h('span',{class:'dot'}),h('span',{},'Checking…'));
run({title:'WoL Host',sub:'Install on the PC you stream from',icon:'monitor',nav:[['setup','Set up','wrench'],['info','This PC','monitor'],['pin','Remote PIN','shield'],['tg','TimeGuard','shield']],subs:{tg:[[0,'Dashboard'],[1,'Accounts'],[2,'Requests'],[3,'Settings']]},pages:PG,foot:[tipChip,admChip],first:()=>M.agent_up?'info':'setup',
  start(){window.__side=S=>{tsChip.className='chip c-'+(!S.tip?'bad':S.tslink?'ok':'warn');tsChip.lastChild.textContent=!S.tip?'Tailscale offline':S.tslink?'Tailscale connected'+(S.tsnet?' · '+S.tsnet:''):'Tailscale: not linked to phone';tsChip.title=S.tip&&S.tsnet?'Connected to Tailscale as '+S.tsnet:'';tsChip.firstChild.classList.toggle('live',!!S.tip&&!!S.tslink);
    tipChip.lastChild.textContent='Tailscale IP: '+(S.tip||'not connected');tipChip.className='chip click c-'+(S.tip?'ok':'bad');
    admChip.className='chip c-'+(S.admin?'ok':'bad');admChip.lastChild.textContent=S.admin?'Administrator':'Not administrator'}}});
</script></body></html>'''

# =====================================================================================================================
#  GPU-accelerated interface (WebView2 / Chromium). The setup / agent logic above is reused unchanged.
#  Needs:  pip install pywebview     (the Microsoft WebView2 runtime ships with Windows 11 and current Windows 10)
#  Flags:  --classic = old customtkinter window      --software-ui = turn GPU drawing off (troubleshooting)
# =====================================================================================================================
class WebApi:
    """Everything the page can call. Public methods are exposed to JavaScript; attributes starting with _ are private."""
    def __init__(self, tg=None):
        self._lock = threading.RLock(); self._rev = 1; self._toast = {"id": 0, "t": "Ready", "c": ""}
        self._busy = False; self._info_busy = False; self._prog = 0.0; self._steps = [{"name": n, "state": "pending"} for n, _ in STEPS]
        self._tip = ""; self._tiles = []; self._rows = []; self._closed = False
        self._page = ""
        self._admin = is_admin()
        self._tg = tg if tg is not None else TgDock(lambda: find_host_hwnd("WoL Host")); self._tg.on_change = self._bump
        threading.Thread(target=self._loop, daemon=True).start()
    def _bump(self):
        with self._lock: self._rev += 1
    def _say(self, t, col=""):
        with self._lock: self._toast = {"id": self._toast["id"] + 1, "t": str(t), "c": col}; self._rev += 1
    def _loop(self):
        while not self._closed:
            self.refresh()
            time.sleep(10)
    def meta(self): return {"def_user": DEF_USER, "def_pw": DEF_PW, "agent_up": bool(agent_up())}
    def poll(self, rev):
        with self._lock:
            if rev == self._rev: return None
            return {"rev": self._rev, "toast": dict(self._toast), "busy": self._busy, "prog": self._prog, "steps": [dict(s) for s in self._steps], "tip": self._tip, "tsnet": getattr(self, "_tsnet", ""), "tslink": getattr(self, "_tslink", False),
                    "tiles": list(self._tiles), "rows": list(self._rows), "admin": self._admin, "login": list(getattr(self, "_login", None) or sun_login()), "tg": self._tg.status(), "accts": list(getattr(self, "_accts", []))}
    def page(self, k): self._page = k
    def on_close(self): self._closed = True; self._tg.close(); return True
    # ---- TimeGuard tab: the page tells where its empty area is (in screen pixels of this window), the TimeGuard window is docked over it
    def copy_text(self, t):
        """Put text on the Windows clipboard (the web page itself is not allowed to). Runs on the GUI thread in the Qt window. -> True when it worked."""
        t = str(t)
        try:
            from PySide6.QtWidgets import QApplication
            app = QApplication.instance()
            if app is not None: app.clipboard().setText(t); return True
        except Exception as e: log(f"copy_text (Qt): {e!r}")
        try:
            r = _run(["clip"], input=t.encode("utf-16le"), capture_output=True, timeout=10)
            if r.returncode == 0: return True
        except Exception as e: log(f"copy_text (clip): {e!r}")
        return False
    def tg_open(self): self._tg.open()
    def tg_place(self, x, y, w, h): self._tg.place(x, y, w, h)
    def tg_hide(self): self._tg.hide()
    def tg_page(self, i): self._tg.page(i)
    def tg_window(self): self._tg.standalone()
    # ---- Remote PIN panel in the TimeGuard tab
    def pin_state(self):
        try: ua = users(); ms = _cache.get("m", (0, []))[1]
        except Exception: ua, ms = [], []
        hp = hostpin_load()
        dual = set(hostpin_dual_users())
        return [{"user": n, "msa": n.lower() in ms, "set": n.lower() in hp, "dual": n.lower() in dual, "exp": int((hp.get(n.lower()) or {}).get("exp") or 0)} for n in ua]
    def pin_set(self, user, pin, amount=0, unit="permanent"):
        """One PIN per account: it signs the account in / out AND is the PIN that wake and stream ask for. `unit` = permanent / days / weeks / months."""
        if not is_admin(): return {"ok": False, "msg": "Run WoL Host as Administrator (right-click > Run as administrator)."}
        user, pin, unit = str(user or ""), str(pin or ""), str(unit or "permanent")
        if user.lower() not in [u.lower() for u in users()]: return {"ok": False, "msg": "That Windows user does not exist (or is disabled) on this PC."}
        try: n = int(amount or 0)
        except Exception: n = 0
        per = {"days": 1, "weeks": 7, "months": 30}.get(unit)                         # a month = 30 days
        if unit != "permanent" and (per is None or not 1 <= n * per <= 3650): return {"ok": False, "msg": "Choose how long the PIN lasts (up to 10 years), or Permanent."}
        secs = 0 if unit == "permanent" else n * per * 86400
        st = "msa" if is_msa(user) else windows_pw_state(user)           # Microsoft accounts always keep their password
        dual = st != "blank"                                              # blank Windows password -> the PIN replaces it; anything else -> PIN (sign-out) + password (sign-in)
        try: hostpin_set(user, pin, "dual" if dual else "blank", secs)
        except Exception as e: return {"ok": False, "msg": str(e)}
        log(f"remote PIN set for {user} ({'PIN for sign-out, PIN + password for sign-in' if dual else 'PIN replaces the blank password'}; {'permanent' if not secs else f'{n} {unit}'})")
        ok, m = access_sync(True)                                         # the phone gets every account's PIN too (it asks for one before it wakes a PC)
        when = "It never expires." if not secs else f"It is removed automatically after {n} {unit if n != 1 else unit[:-1]}."
        if dual: txt = f"PIN set for {user}. The PIN alone signs them out; signing them in needs this PIN and their {'Microsoft account' if st == 'msa' else 'Windows'} password."
        else: txt = f"PIN set for {user}. Their Windows password is blank, so only this PIN can sign them in or out remotely."
        return {"ok": True, "warn": not ok, "msg": f"{txt} It is also the PIN for waking and streaming as {user}. {when}" + ("" if ok else " " + m)}
    def pin_clear(self, user):
        if not is_admin(): return {"ok": False, "msg": "Run WoL Host as Administrator (right-click > Run as administrator)."}
        hostpin_clear(str(user or "")); log(f"remote PIN removed for {user}")
        ok, m = access_sync(True)
        return {"ok": True, "warn": not ok, "msg": f"PIN removed for {user}. Remote sign-in, waking and streaming as {user} are off until you set one again (or give the account a Windows password again)." + ("" if ok else " " + m)}
    # ---- status of the PINs and of the phone copy (Remote PIN tab)
    def access_state(self):
        a = accesspin_active(); st = sync_state(); ip = relay_ip(); lk = bool(ip and phone_secret())
        return {"required": bool(a), "count": len(a), "now": int(time.time()),
                "phone": {"ip": ip, "linked": lk, "ok": bool(st.get("ok")) if lk else None, "msg": str(st.get("msg") or ""), "t": int(st.get("t") or 0)}}
    def access_sync_now(self):
        ok, m = access_sync(True); return {"ok": ok, "msg": m or ("In sync with the phone." if ok else "Not synced.")}

    def _work(self, fn):
        if self._busy: self._say("Another task is still running - please wait.", "warn"); return False
        self._busy = True; self._bump()
        def run():
            try: fn()
            except Exception as e: log(f"task error: {e!r}"); self._say(f"✖ {e}", "bad")
            finally: self._busy = False; self._bump()
        threading.Thread(target=run, daemon=True).start(); return True

    def refresh(self):
        if self._info_busy: return
        self._info_busy = True
        try:
            sun, inst, ag, tip = sun_up(), sun_installed(), agent_up(), ts_ip()
            lg = login_ok() if sun else False; wm = physical_macs(); ms = macs(); ss = sessions()
            who = ", ".join(f"{x['user']} ({x['state']})" for x in ss)
            rows = [["Computer name", socket.gethostname(), False], ["Tailscale address", tip or "Not connected", bool(tip)], ["Signed-in user", who or "Nobody (sign-in screen)", False]] + \
                   [["MAC (physical)" if m in wm else "MAC (virtual)", m, True] for m in ms]
            tu = ts_unattended() if tip else None
            lk = relay_linked() if tip else False
            tnet = ts_label() if tip else ""                                                   # e-mail account / tailnet name of this PC's Tailscale login
            if tnet: rows.insert(2, ["Tailscale account" if "@" in tnet else "Tailscale network", tnet, True])
            tiles = [["Tailscale", (("Connected" + (f" · {tnet}" if tnet else "")) if lk else "Not linked to phone: paste a token") if tip else "Offline", "ok" if lk else "bad"],
                     ["Before sign-in", "Tailscale stays on" if tu else "Stops at sign-in: press UPDATE" if tu is False else "Unknown", "ok" if tu else "bad" if tu is False else "mut"],
                     ["Sunshine", "Running" if sun else "Waiting for sign-in" if inst and not ss else "Stopped" if inst else "Not installed", "ok" if sun else "mut" if inst and not ss else "bad"],
                     ["Host agent", "Running" if ag else "Stopped", "ok" if ag else "bad"],
                     ["Pairing login", (f"{sun_login()[0]} / {sun_login()[1]}" if lg else "Needs fix") if sun else "Sunshine off", "ok" if lg else "warn" if sun else "mut"]]
            try: ua = users(); ms = _cache.get("m", (0, []))[1]; accts = [[n, n.lower() in ms] for n in ua]
            except Exception: accts = []
            with self._lock: self._tip, self._tiles, self._rows, self._login, self._accts, self._tsnet, self._tslink = tip or "", tiles, rows, list(sun_login()), accts, tnet, bool(lk); self._rev += 1
        except Exception as e: log(f"info error: {e!r}")
        finally: self._info_busy = False

    def setup(self, tok):
        if not is_admin(): return self._say("Run WoL Host as Administrator (right-click → Run as administrator).", "bad")
        tok = (tok or "").strip()
        for s in self._steps: s["state"] = "pending"
        self._prog = 0.0; self._bump()
        def f():
            fails, first = 0, ""
            for i, (name, fn) in enumerate(STEPS):
                self._steps[i]["state"] = "work"; self._steps[i]["msg"] = ""; self._bump(); self._say(f"{name}…")
                try: ok, msg = fn(tok)
                except Exception as e: ok, msg = False, str(e)
                log(f"step {name}: {ok} {msg}"); self._steps[i]["state"] = "ok" if ok else "fail"; self._steps[i]["msg"] = "" if ok else str(msg)[:600]; self._prog = (i + 1) / len(STEPS); self._bump()
                if not ok: fails += 1; first = first or f"{name}: {msg}"; self._say(f"✖ {name}: {msg}", "bad")
                if not ok and fn is step_join: break                          # nothing else works without the phone's Tailscale account
            self._say("✔ This PC is ready. Add its Tailscale address in the client app." if not fails else f"{fails} step(s) failed - {first[:220]}", "ok" if not fails else "warn")
            self.refresh()
        self._work(f)
    def join(self, tok):
        """Join button: only joins the phone's Tailscale account with the token (no other Set up step)."""
        if not is_admin(): return self._say("Run WoL Host as Administrator (right-click → Run as administrator).", "bad")
        tok = (tok or "").strip()
        for s in self._steps: s["state"] = "pending"; s["msg"] = ""
        self._prog = 0.0; self._bump()
        def mark(i, state, msg=""): self._steps[i]["state"] = state; self._steps[i]["msg"] = msg; self._prog = 1.0 if (i == 1 and state == "ok") else self._prog; self._bump()
        def f():
            ok, msg = join_only(tok, mark, self._say)
            self._say(("✔ " if ok else "✖ ") + str(msg)[:300], "ok" if ok else "bad")
            self.refresh()
        self._work(f)
    def restart(self):
        if not is_admin(): return self._say("Run WoL Host as Administrator.", "bad")
        self._say("Updating the agent, checking the Sunshine login and repairing TimeGuard protection…")
        def f():
            ok, _ = step_agent(None)
            if sun_installed(): sun_task(); sh("taskkill /f /im sunshine.exe", 20); time.sleep(1)
            lg, lm = ensure_login() if sun_installed() else (False, "Sunshine is not installed - run Set up")
            self._say("Repairing TimeGuard protection…"); tok, tmsg = tg_repair()
            if not lg: self._say(f"✖ {lm}", "bad")
            elif not ok: self._say(f"✖ Agent did not start. Log: {log_tail()}", "bad")
            elif not tok: self._say(f"✔ Agent updated and running · ✖ {tmsg}", "warn")
            else: self._say(f"✔ Agent updated and running · Sunshine login is {sun_login()[0]} / {sun_login()[1]} · {tmsg}", "ok")
            self.refresh()
        self._work(f)
    def remove_tg(self):
        if not is_admin(): return self._say("Run WoL Host as Administrator.", "bad")
        self._say("Removing the TimeGuard service and turning the WoL Host agent off…")
        def f():
            ok, msg = remove_all_services(); self._say(("✔ " if ok else "✖ ") + msg, "ok" if ok else "bad"); self.refresh()
        self._work(f)
    def get_pcname(self): return pc_label() or socket.gethostname()
    def set_pcname(self, name):
        if not is_admin(): self._say("Run WoL Host as Administrator.", "bad"); return None
        try: n = set_pc_label(name)
        except Exception as e: self._say(f"✖ Could not save the name: {e}", "bad"); return None
        self._say(f"✔ This PC is now called “{n}” in WoL Remote." if n else "✔ Name cleared - WoL Remote shows this PC's Windows name.", "ok"); return n or socket.gethostname()
    def set_sun_login(self, user, pw):
        """Change the Sunshine web/API username and password (what the agent uses to enter pairing PINs)."""
        if not is_admin(): return self._say("Run WoL Host as Administrator.", "bad")
        user, pw = (user or "").strip(), pw or ""
        bad = check_sun_login(user, pw)
        if bad: return self._say(f"✖ {bad}", "bad")
        if not sun_installed(): return self._say("✖ Sunshine is not installed - run Set up first.", "bad")
        self._say("Changing the Sunshine login…")
        def f():
            ok, msg = ensure_login((user, pw)); self._say(f"✔ {msg}" if ok else f"✖ {msg}", "ok" if ok else "bad"); self.refresh()
        self._work(f)
    def start_sun(self):
        if not is_admin(): return self._say("Run WoL Host as Administrator.", "bad")
        def f():
            ok = sun_start() if sun_installed() else False
            self._say("✔ Sunshine is running." if ok else "Nobody is signed in: Sunshine only runs inside a signed-in session, by design." if sun_installed() and not has_session() else "✖ Sunshine did not start (is it installed? run Set up).", "ok" if ok else "warn")
            self.refresh()
        self._work(f)
    def open_sun_ui(self):
        import webbrowser; webbrowser.open(f"https://localhost:{SUN_UI}")

def _webview2_present():
    if os.name != "nt": return True
    for root in ("HKLM\\SOFTWARE\\WOW6432Node", "HKLM\\SOFTWARE", "HKCU\\SOFTWARE"):
        try:
            r = subprocess.run(["reg", "query", root + "\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "/v", "pv"], capture_output=True, text=True, creationflags=0x08000000)
            if r.returncode == 0 and "pv" in r.stdout: return True
        except Exception: pass
    return False

def run_web_gui():
    """Open the GPU-accelerated window. True = it ran; False = it could not start (the caller falls back to the classic window)."""
    try:
        import webview
        if os.name == "nt" and not _webview2_present():
            subprocess.run(["winget", "install", "-e", "--id", "Microsoft.EdgeWebView2Runtime", "--silent", "--accept-source-agreements", "--accept-package-agreements"], capture_output=True, creationflags=0x08000000)
        flags = "--disable-gpu" if "--software-ui" in sys.argv else "--enable-gpu-rasterization --ignore-gpu-blocklist --enable-zero-copy --enable-features=CanvasOopRasterization"
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (os.environ.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "") + " " + flags).strip()
        api = WebApi()
        win = webview.create_window("WoL Host", html=HTML, js_api=api, width=1120, height=780, min_size=(940, 680), background_color="#070a14", text_select=True)
        win.events.closing += api.on_close
        webview.start(gui="edgechromium" if os.name == "nt" else None)
        return True
    except Exception:
        import traceback; log("web UI failed, using classic window: " + traceback.format_exc()[-800:]); return False

# ---------------- Qt window: TimeGuard lives INSIDE it ----------------
# The page (same HTML as the WebView2 version) runs in a QWebEngineView (Chromium, GPU drawing like WebView2). Because the window is Qt, TimeGuard's
# own Qt window (timeguard.Main) is simply created as a child widget of it and laid over the TimeGuard tab: one process, one event loop, no
# SetParent / DPI tricks - it cannot turn into a separate window. The page talks to Python through QWebChannel (window.pywebview.api.* keeps working).
class QtTg:
    """Same interface as TgDock (open / place / hide / close / status), but TimeGuard is a widget of this process."""
    def __init__(self, host, owner):
        self.host, self.owner, self.win = host, owner, None          # host: widget that holds the page; owner: the top-level window (parent of the password box)
        self.state, self.msg, self.mode, self.rect, self.visible = "idle", "", "embedded", None, False
        self.on_change = lambda: None
    def status(self): return {"state": self.state, "msg": self.msg, "mode": self.mode, "running": self.win is not None, "pending": int(getattr(self.win, "pending", 0) or 0)}
    def _set(self, state, msg=""): self.state, self.msg = state, msg; self.on_change()
    def check(self):
        if os.name != "nt": return "TimeGuard only works on Windows."
        return ""
    def open(self):                                                  # GUI thread
        if self.state == "starting": return
        if self.win is not None: self._set("ready"); self.place_now(); return
        bad = self.check()
        if bad: return self._set("error", bad)
        self._set("starting", "Starting TimeGuard… (type the admin password if it asks for one)")
        try:
            tgm = load_timeguard()
            if not tgm.authenticate(tgm.jload(tgm.CFG, {}), self.owner): return self._set("locked", "TimeGuard is locked: the admin password was not entered.")
            from PySide6.QtWidgets import QApplication
            QApplication.instance().setStyleSheet(tgm.QSS)           # TimeGuard's dark look (its dialogs, menus, tooltips)
            self.win = tgm.make_embedded(self.host); self.win.hide()
            log("timeguard created inside the host window"); self._set("ready"); self.place_now()
        except Exception as e:
            import traceback; log("timeguard (in-process) failed: " + traceback.format_exc()[-900:]); self.win = None
            self._set("error", f"TimeGuard could not start: {e}")
    def page(self, i):                                               # TimeGuard sub-menu (Dashboard / Accounts / Requests / Settings)
        if self.win is not None: self.win.go(int(i)); self.on_change()
    def place(self, x, y, w, h): self.rect, self.visible = (int(x), int(y), int(w), int(h)), True; self.place_now()
    def place_now(self):
        if self.win is None or not self.visible or not self.rect: return
        x, y, w, h = self.rect; self.win.setGeometry(x, y, w, h); self.win.show(); self.win.raise_()
    def hide(self):
        self.visible = False
        if self.win is not None: self.win.hide()
    def close(self):
        w, self.win, self.state = self.win, None, "idle"
        if w is not None:
            try: w._quit = True; w.close()                           # lets TimeGuard save and end its live connections
            except Exception as e: log(f"timeguard close: {e!r}")
    def standalone(self):                                            # last resort, only offered when TimeGuard could not start here
        try: subprocess.Popen(helper_argv(["--tg-gui"]), **NOWIN)
        except Exception as e: log(f"timeguard standalone failed: {e!r}")

def run_qt_gui():
    """Open the Qt window. True = it ran; False = it could not start (the caller falls back to the WebView2 window)."""
    try:
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " " + ("--disable-gpu" if "--software-ui" in sys.argv else "--enable-gpu-rasterization --ignore-gpu-blocklist --enable-zero-copy")).strip()
        from PySide6.QtCore import Qt, QObject, Slot, Signal, QUrl, QTimer, QFile, QIODevice
        from PySide6.QtGui import QColor
        from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWebChannel import QWebChannel
        app = QApplication.instance() or QApplication(sys.argv[:1])
        app.setStyle("Fusion")
        f = QFile(":/qtwebchannel/qwebchannel.js")
        if not f.open(QIODevice.ReadOnly): raise RuntimeError("qwebchannel.js is missing from this PySide6 install")
        qwc = bytes(f.readAll()).decode("utf-8"); f.close()
        anchor = "<script>const ICONS={"
        if HTML.count(anchor) != 1: raise RuntimeError("page layout changed (script anchor)")
        shim = ("window.__QT=true;(function(){const P={};let N=0;window.__ret=(i,o)=>{const p=P[i];if(!p)return;delete P[i];(o&&'e' in o)?p[1](new Error(o.e)):p[0](o?o.v:null)};"
                "new QWebChannel(qt.webChannelTransport,ch=>{const B=ch.objects.bridge;window.pywebview={api:new Proxy({},{get:(_,m)=>(...a)=>new Promise((ok,no)=>{const i=++N;P[i]=[ok,no];B.call(i,String(m),JSON.stringify(a))})})};"
                "window.dispatchEvent(new Event('pywebviewready'))})})();")
        page_html = HTML.replace(anchor, "<script>" + qwc + "</script><script>" + shim + "</script>" + anchor, 1)

        class Bridge(QObject):
            ret = Signal(int, str)
            def __init__(self, view): super().__init__(); self.view = view; self.api = None; self.ret.connect(self._deliver)
            def _deliver(self, cid, js): self.view.page().runJavaScript(f"window.__ret({cid},{js})")
            @Slot(int, str, str)
            def call(self, cid, name, args):
                fn = None if name.startswith("_") else getattr(self.api, name, None)
                try: a = json.loads(args or "[]")
                except Exception: a = []
                def work():
                    try: r = {"v": fn(*a)} if callable(fn) else {"e": f"unknown method {name}"}
                    except Exception as e: log(f"api {name}: {e!r}"); r = {"e": str(e)}
                    try: out = json.dumps(r, default=str)
                    except Exception as e: out = json.dumps({"e": str(e)})
                    self.ret.emit(cid, out)                       # queued to the GUI thread
                if name.startswith("tg_") or name == "copy_text": QTimer.singleShot(0, work)             # touches Qt widgets: GUI thread
                else: threading.Thread(target=work, daemon=True).start()          # everything else may take long: never block the window

        class Win(QMainWindow):
            def closeEvent(self, e):
                try: api.on_close()
                except Exception as ex: log(f"close: {ex!r}")
                super().closeEvent(e)
        win = Win(); win.setWindowTitle("WoL Host"); win.resize(1120, 780); win.setMinimumSize(1000, 700)
        central = QWidget(); central.setObjectName("wolhost"); central.setStyleSheet("#wolhost{background:#070a14}")
        lay = QVBoxLayout(central); lay.setContentsMargins(0, 0, 0, 0)
        view = QWebEngineView(central); lay.addWidget(view); win.setCentralWidget(central)
        view.page().setBackgroundColor(QColor("#070a14")); view.setContextMenuPolicy(Qt.NoContextMenu)
        try:
            from PySide6.QtWebEngineCore import QWebEngineSettings
            view.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, True)
        except Exception as e: log(f"clipboard setting: {e!r}")
        api = WebApi(QtTg(central, win))
        bridge = Bridge(view); bridge.api = api
        channel = QWebChannel(view.page()); channel.registerObject("bridge", bridge); view.page().setWebChannel(channel)
        view.setHtml(page_html, QUrl("https://wolhost.invalid/"))
        win.show(); app.exec()
        return True
    except Exception:
        import traceback; log("Qt window failed, trying the WebView2 window: " + traceback.format_exc()[-900:]); return False



# ======================================================================================================================================
# TimeGuard (the former timeguard.py) - embedded as text and loaded in this process as the module "timeguard", so wol_host.py is the only file.
# Edit it right here (everything between the two ===== lines); nothing else is needed.
# ======================================================================================================================================
def load_timeguard():
    m = sys.modules.get("timeguard")
    if m is not None: return m
    import types
    m = types.ModuleType("timeguard"); m.__file__ = os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)
    m._onedir, m.copy_app_dir = _onedir, copy_app_dir
    sys.modules["timeguard"] = m
    try: exec(compile(_TG_SRC, "timeguard(embedded in wol_host.py)", "exec"), m.__dict__)
    except BaseException:
        sys.modules.pop("timeguard", None); raise
    return m

_TG_SRC = r'''
"""
TimeGuard - per-account screen-time manager for Windows (TimeBoss-style).

Roles of this file:
  timeguard.py               -> admin GUI (asks for UAC elevation)
  timeguard.py --tg-engine   -> background enforcer, runs as SYSTEM (scheduled task)
  timeguard.py --tg-agent    -> countdown widget, runs in each user's session (warnings + remaining time)
(the old names --engine / --agent still work when this file is started on its own)

Inside WoL Host this file is imported as a module: wol_host.py starts it with --tg-gui --embed <hwnd> <info file>
and docks its window into the "TimeGuard" tab (see run_embedded at the bottom). The --tg-* names exist because
WoL Host already uses --agent for its own agent, and a single .exe must tell the two apart.
"""
import sys, os, re, math, tempfile, json, time, shutil, hashlib, secrets, subprocess, threading, traceback, datetime as dt
from pathlib import Path, PureWindowsPath

APP = "TimeGuard"
TASK = "TimeGuardEngine"
DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP
CFG, USE, STA = DATA / "config.json", DATA / "usage.json", DATA / "status.json"
REMOVED = DATA / "removed.flag"  # written by "Remove protection": engine and agents quit when they see it
AGENT_TASK = "TimeGuardAgent"
LIVE = DATA / "live"  # screen frames: readable by administrators and SYSTEM only
REQ = DATA / "requests"  # install requests, one file each: only SYSTEM (the agent) and administrators can write here
NOWIN = 0x08000000 if os.name == "nt" else 0


# ───────────────────────── shared logic ─────────────────────────
def jload(p, default):
    try:
        return json.loads(Path(p).read_text("utf-8"))
    except Exception:
        return default


def jsave(p, obj):
    """Write a JSON file. Replacing a file can briefly be refused (a virus scanner or another process has it open, or an old
    copy has a stricter access list), so retry, and finally write in place instead of failing the whole round."""
    data = json.dumps(obj)
    tmp = Path(str(p) + ".tmp")
    for i in range(4):
        try:
            tmp.write_text(data, "utf-8")
            os.replace(tmp, p)
            return
        except PermissionError:
            time.sleep(0.15 * (i + 1))
    try:
        tmp.unlink()
    except OSError:
        pass
    Path(p).write_text(data, "utf-8")  # not atomic, but better than losing the update (raises if even this is refused)


def _exe(name):
    """Full path of a Windows program. A 32-bit Python on 64-bit Windows would otherwise get the wrong (or no)
    System32 folder; 'Sysnative' gives it the real one."""
    if os.name != "nt" or os.path.isabs(name) or os.sep in name:
        return name
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    base = name if name.lower().endswith(".exe") else name + ".exe"
    cands = [root / "Sysnative" / base, root / "System32" / base,
             root / "System32" / "WindowsPowerShell" / "v1.0" / base, root / "SysWOW64" / base]
    return next((str(c) for c in cands if c.is_file()), name)


def run(*cmd):
    cmd = list(cmd)
    cmd[0] = _exe(cmd[0])
    try:
        return subprocess.run(cmd, capture_output=True, text=True, creationflags=NOWIN)
    except FileNotFoundError:  # report WHICH program is missing instead of a bare "[WinError 2]"
        return subprocess.CompletedProcess(cmd, 127, "", f"Windows program not found: {cmd[0]}")


def default_user():
    return {"enabled": True, "credit_min": 1440, "weekly": 0, "monthly": 0,
            "use_schedule": False, "from": "07:00", "to": "21:00", "auto_account": False,
            "warn": 5, "action": "logoff", "restrict_drives": False, "block_drives": []}


def user_auto_logoff(cfg, name):
    """Accounts > <user> (needs 'Manage' on) > 'Sign out after 15 minutes of inactivity'. An entry without its own value falls back to the old global switch."""
    u = cfg.get("users", {}).get(name)
    if not u or not u.get("enabled"):
        return False
    return bool(u["auto_logoff"]) if "auto_logoff" in u else bool(cfg.get("auto_logoff", False))


def total_used(ud):
    """Seconds this account has used in total since it was first managed."""
    return ud.get("_total", sum(v for k, v in ud.items() if k[:2] == "20"))


def schedule_state(u, now):
    """(allowed right now?, end of the current allowed window) for the 'allowed hours' setting."""
    f = dt.datetime.combine(now.date(), dt.time.fromisoformat(u["from"]))
    t = dt.datetime.combine(now.date(), dt.time.fromisoformat(u["to"]))
    if f <= t:
        return f <= now < t, t
    return now >= f or now < t, (t if now < t else t + dt.timedelta(days=1))  # overnight, e.g. 18:00 -> 06:00


def remaining_info(u, usage, now=None):
    """(seconds left or None, what limits it: 'balance' | 'weekly' | 'monthly' | 'hours:HH:MM' | 'closed:HH:MM')."""
    now = now or dt.datetime.now()
    today = now.date()
    used = lambda d: usage.get(d.isoformat(), 0)
    left = []
    if u.get("credit_min") is not None:  # total time balance - it does not reset each day
        left.append((u["credit_min"] * 60 - total_used(usage), "balance"))
    if u.get("weekly"):
        mon = today - dt.timedelta(days=today.weekday())
        left.append((u["weekly"] * 60 - sum(used(mon + dt.timedelta(days=i)) for i in range(7)), "weekly"))
    if u.get("monthly"):
        ym = today.isoformat()[:7]
        left.append((u["monthly"] * 60 - sum(v for k, v in usage.items() if k[:7] == ym), "monthly"))
    if u.get("use_schedule"):
        ok, end = schedule_state(u, now)
        left.append(((end - now).total_seconds(), "hours:" + end.strftime("%H:%M")) if ok
                    else (0, "closed:" + u["from"]))
    return min(left, key=lambda x: x[0]) if left else (None, None)


def remaining(u, usage, now=None):
    """Seconds left for this account right now. None = unlimited."""
    return remaining_info(u, usage, now)[0]


def fmt(s):
    if s is None or s < 0:
        return "Unlimited"
    s = int(max(s, 0))
    h, m = divmod(s // 60, 60)
    return f"{h} h {m:02d} m" if h else (f"{m} m" if m else f"{s} s")


def clock(s):
    s = int(max(s, 0))
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"


def service_alive():
    try:
        return time.time() - STA.stat().st_mtime < 20
    except OSError:
        return False


# ───────────────────────── install requests ─────────────────────────


def clean_text(s, n):
    """User-typed text: no control characters, single line, limited length."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(s or "")).strip()[:n]


def list_requests():
    """All install requests, newest first."""
    out = []
    try:
        files = list(REQ.glob("*.json"))
    except OSError:
        return out
    for f in files:
        r = jload(f, None)
        if isinstance(r, dict) and re.fullmatch(r"[0-9a-f]{12}", str(r.get("id", ""))):
            out.append(r)
    out.sort(key=lambda r: r.get("ts", 0), reverse=True)
    return out


def decide_request(rid, status, note="", launch=None):
    """(admin GUI) Approve or deny a pending request. Returns False if it was already decided or is gone."""
    if not re.fullmatch(r"[0-9a-f]{12}", str(rid)):
        return False
    f = REQ / f"{rid}.json"
    r = jload(f, None)
    if not isinstance(r, dict) or r.get("status") != "pending":
        return False
    r.update(status=status, note=clean_text(note, 200), decided_ts=time.time())
    if launch:
        r["launch"] = launch
    jsave(f, r)
    return True


def file_sha256(path, limit=300 * 2**20):
    """SHA-256 of a file ('' if it is missing, unreadable or very large)."""
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > limit:
            return ""
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def auto_request(user, program, path, hint, sha):
    """(engine, SYSTEM) File a request because a program of a limited account asked Windows for administrator
    rights. Returns the id of the new (or already open) request, or None."""
    if not jload(CFG, {}).get("install_requests", True):
        return None
    mine = [r for r in list_requests() if r.get("user") == user and r.get("status") == "pending"]
    for r in mine:  # the same program is already waiting: do not pile up requests
        if time.time() - r.get("ts", 0) < 600 and ((path and r.get("path") == path) or (not path and not r.get("path") and r.get("auto"))):
            return r["id"]
    if len(mine) >= 10:
        return None
    REQ.mkdir(parents=True, exist_ok=True)
    rid = secrets.token_hex(6)
    jsave(REQ / f"{rid}.json", {"id": rid, "user": user, "program": clean_text(program, 80) or "Unknown program",
                                "link": "", "reason": "", "ts": time.time(), "status": "pending", "auto": True,
                                "path": clean_text(path, 260), "sha256": sha, "hint": clean_text(hint, 200)})
    return rid



# ───────────────────────── accounts ─────────────────────────
def local_accounts():
    """[(name, is_admin)] for enabled local accounts. [] if Windows can't tell us (fail safe)."""
    ps = ("$a=@((Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue).SID.Value);"
          "Get-LocalUser | ForEach-Object { $_.Name + '|' + [int]($a -contains $_.SID.Value) + '|' + [int]$_.Enabled }")
    try:
        out = []
        # accounts that TimeGuard itself disabled outside the allowed hours must stay in the list
        mine = {k for k, u in jload(CFG, {}).get("users", {}).items() if u.get("auto_account")}
        for line in run("powershell", "-NoProfile", "-Command", ps).stdout.splitlines():
            parts = line.strip().rsplit("|", 2)
            if len(parts) == 3 and (parts[2] == "1" or parts[0].lower() in mine):
                out.append((parts[0], parts[1] == "1"))
        return out if any(a for _, a in out) else []  # no admin found = lookup failed
    except Exception:
        return []


_adm = {"t": 0.0, "names": None}


def admin_names():
    """Lower-case admin account names; None if never determined (then nothing is enforced)."""
    if _adm["names"] is None or time.time() - _adm["t"] > 60:
        acc = local_accounts()
        if acc:
            _adm["names"] = {n.lower() for n, a in acc if a}
        _adm["t"] = time.time()
    return _adm["names"]


# ───────────────────────── engine (SYSTEM) ─────────────────────────
_QSTATES = {"active", "disc", "disconnected", "idle", "conn", "connected", "down", "listen", "reset", "shadow", "init"}


def sessions():
    """[(user name lower-case, session id, state)] from `quser`. User names may contain spaces ("Himanshu boss"), so the session id is found as
    the number that is followed by a state word, and everything before it (minus the session name, e.g. console / rdp-tcp#3) is the name."""
    out = []
    for line in run("quser").stdout.splitlines()[1:]:
        t = line.replace(">", " ", 1).split()
        for i in range(1, len(t) - 1):
            if t[i].isdigit() and t[i + 1].lower() in _QSTATES:
                name = t[:i]
                if len(name) > 1 and (name[-1].lower() == "console" or name[-1].lower().startswith(("rdp-", "ica-"))):
                    name = name[:-1]  # connected sessions have a session name column, disconnected ones do not
                out.append((" ".join(name).lower(), int(t[i]), t[i + 1].lower()))
                break
    return out


def log(msg):
    try:
        p = DATA / "engine.log"
        if p.exists() and p.stat().st_size > 200_000:
            p.unlink()
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")
    except OSError:
        pass


def launch_in_session(session_id, cmdline, cwd=None, desktop="winsta0\\default", as_user=False):
    """(SYSTEM only) Start a process on the desktop of the given user session. Normally it runs as SYSTEM, so a standard user cannot end or close it.
    as_user=True: run it with the signed-in user's OWN token instead. Windows (UIPI) drops keyboard / mouse input that Sunshine injects as the user
    while a higher-privilege (SYSTEM) window has the focus, so anything with a window must run as the user, or the stream shows but does not react."""
    import ctypes
    from ctypes import wintypes as wt
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SI(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                    ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                    ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                    ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                    ("hStdError", wt.HANDLE)]

    class PI(ctypes.Structure):
        _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD),
                    ("dwThreadId", wt.DWORD)]

    k32.GetCurrentProcess.restype = wt.HANDLE
    adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    adv.DuplicateTokenEx.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                     ctypes.POINTER(wt.HANDLE)]
    adv.SetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
    adv.CreateProcessAsUserW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                         wt.BOOL, wt.DWORD, ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(SI),
                                         ctypes.POINTER(PI)]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    if as_user:  # the user's own token (needs SYSTEM): the process gets the user's privilege level and the user's environment (TEMP, APPDATA ...)
        wts, ue = ctypes.WinDLL("wtsapi32", use_last_error=True), ctypes.WinDLL("userenv", use_last_error=True)
        wts.WTSQueryUserToken.argtypes = [wt.ULONG, ctypes.POINTER(wt.HANDLE)]
        ue.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(ctypes.c_void_p), wt.HANDLE, wt.BOOL]
        ue.DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]
        ut = wt.HANDLE()
        if wts.WTSQueryUserToken(session_id, ctypes.byref(ut)):
            env = ctypes.c_void_p()
            try:
                have_env = bool(ue.CreateEnvironmentBlock(ctypes.byref(env), ut, False))
                si = SI()
                si.cb = ctypes.sizeof(SI)
                si.lpDesktop = desktop
                pi = PI()
                buf = ctypes.create_unicode_buffer(cmdline)
                if not adv.CreateProcessAsUserW(ut, None, buf, None, None, False, 0x08000000 | (0x400 if have_env else 0),  # CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
                                                env.value if have_env else None, cwd, ctypes.byref(si), ctypes.byref(pi)):
                    raise ctypes.WinError(ctypes.get_last_error())
                k32.CloseHandle(pi.hProcess)
                k32.CloseHandle(pi.hThread)
                return
            finally:
                if env.value:
                    ue.DestroyEnvironmentBlock(env)
                k32.CloseHandle(ut)
        log(f"no user token for session {session_id} (error {ctypes.get_last_error()}): starting the helper as SYSTEM instead")
    tok, dup = wt.HANDLE(), wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0xF01FF, ctypes.byref(tok)):  # TOKEN_ALL_ACCESS
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not adv.DuplicateTokenEx(tok, 0xF01FF, None, 2, 1, ctypes.byref(dup)):  # impersonation, primary token
            raise ctypes.WinError(ctypes.get_last_error())
        sid = wt.DWORD(session_id)
        if not adv.SetTokenInformation(dup, 12, ctypes.byref(sid), ctypes.sizeof(sid)):  # TokenSessionId
            raise ctypes.WinError(ctypes.get_last_error())
        si = SI()
        si.cb = ctypes.sizeof(SI)
        si.lpDesktop = desktop
        pi = PI()
        buf = ctypes.create_unicode_buffer(cmdline)
        if not adv.CreateProcessAsUserW(dup, None, buf, None, None, False, 0x08000000, None, cwd,
                                        ctypes.byref(si), ctypes.byref(pi)):  # CREATE_NO_WINDOW
            raise ctypes.WinError(ctypes.get_last_error())
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
    finally:
        k32.CloseHandle(tok)
        if dup:
            k32.CloseHandle(dup)


def agent_alive(sid):
    """The widget program holds a named mutex while it runs in session `sid`."""
    try:
        import ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenMutexW.restype = ctypes.c_void_p
        k.OpenMutexW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k.OpenMutexW(0x00100000, 0, f"Global\\TimeGuardAgent-{sid}")  # SYNCHRONIZE
        if h:
            k.CloseHandle(h)
            return True
    except Exception:
        pass
    return False


_launched = {}
_backoff = {}  # helper key -> (launches since it was last seen running, earliest next launch)


def may_launch(key, alive):
    """Throttle helper launches. A helper that dies at once (for example the packaged .exe cannot unpack itself: 'Failed to extract cv2.pyd') must NOT be
    started again every 10 s: every failure pops an error box up on the user's desktop, and that box takes the keyboard / mouse focus from the stream.
    Waits 10 s, 20 s, 40 s ... at most 15 min between launches; a helper seen running resets it."""
    now = time.time()
    if alive:
        _backoff.pop(key, None)
        return False
    n, nxt = _backoff.get(key, (0, 0.0))
    if now < nxt:
        return False
    _backoff[key] = (n + 1, now + min(10 * 2 ** n, 900))
    return True


def ensure_agent(user, sid):
    """Make sure the countdown widget is running in this user's session; restart it if it is gone."""
    if not may_launch(("agent", sid), agent_alive(sid)):
        return
    base = [sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)])
    cmd = " ".join(f'"{x}"' for x in base) + f' --tg-agent --user "{user}"'
    try:
        launch_in_session(sid, cmd, as_user=True)     # the widget / tray / popups have windows: as the user, never as SYSTEM (see launch_in_session)
    except Exception as e:
        log(f"could not start the widget for {user} (session {sid}): {e}")


_acct = {}  # account name -> (enabled by us?, when we last set it)


def sync_accounts(users, admins):
    """Enable a limited user's Windows account inside its allowed hours and disable it outside them."""
    if admins is None:
        return
    now, tnow, active = dt.datetime.now(), time.time(), set()
    for name, u in users.items():
        if name in admins or not (u.get("enabled") and u.get("auto_account") and u.get("use_schedule")):
            continue
        active.add(name)
        want = schedule_state(u, now)[0]
        last = _acct.get(name)
        if last is None or last[0] != want or tnow - last[1] > 120:
            run("net", "user", name, "/active:yes" if want else "/active:no")
            _acct[name] = (want, tnow)
    for name in list(_acct):  # option switched off or account no longer managed: give the account back
        if name not in active:
            run("net", "user", name, "/active:yes")
            del _acct[name]


import ctypes
from ctypes import wintypes as wt


# ───────────────────────── admin-prompt watcher (engine) ─────────────────────────
class _PE32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


def process_list():
    """[(pid, parent pid, exe name)] of all running processes (fast, no subprocess)."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PE32)]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    h, out = k.CreateToolhelp32Snapshot(0x2, 0), []  # TH32CS_SNAPPROCESS
    if h in (None, ctypes.c_void_p(-1).value):
        return out
    try:
        e = _PE32()
        e.dwSize = ctypes.sizeof(_PE32)
        ok = k.Process32FirstW(h, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.th32ParentProcessID, e.szExeFile))
            ok = k.Process32NextW(h, ctypes.byref(e))
    finally:
        k.CloseHandle(h)
    return out


def proc_path(pid):
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = ctypes.c_void_p
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        buf, n = ctypes.create_unicode_buffer(1024), wt.DWORD(1024)
        return buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else ""
    finally:
        k.CloseHandle(h)


def proc_session(pid):
    sid = wt.DWORD()
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    return sid.value if k.ProcessIdToSessionId(pid, ctypes.byref(sid)) else -1


def proc_cmdline(pid):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"],
                           capture_output=True, text=True, creationflags=NOWIN, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


_NOT_APPS = {"svchost.exe", "consent.exe", "explorer.exe", "services.exe", "winlogon.exe", "csrss.exe", "conhost.exe",
             "dllhost.exe", "runtimebroker.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe", "searchhost.exe",
             "dwm.exe", "lsass.exe", "wininit.exe", "logonui.exe", "fontdrvhost.exe"}
_PATH_START = re.compile(rb"[A-Za-z]\x00:\x00\\\x00")  # "X:\" as UTF-16 text
_EXE_PATH = re.compile(r'[A-Za-z]:\\[^<>|"?*\x00-\x1f]*?\.(?:exe|msi|bat|cmd|msc|com)(?![A-Za-z0-9_])', re.I)


class _MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def paths_in(data, counts):
    """Collect program paths (UTF-16 text such as C:\\Users\\x\\Setup.exe) found in a block of memory."""
    for m in _PATH_START.finditer(data):
        if m.start() % 2:
            continue
        text = data[m.start(): m.start() + 1040].decode("utf-16-le", "ignore").split("\x00", 1)[0]
        pm = _EXE_PATH.match(text)
        if pm:
            counts[pm.group(0)] = counts.get(pm.group(0), 0) + 1


def scan_process_paths(pid):
    """{path: how often} of program paths in the memory of a process. The Windows admin prompt (consent.exe) holds
    the path of the program that asked for administrator rights, because it shows it to the user."""
    counts = {}
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = ctypes.c_void_p
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.VirtualQueryEx.restype = ctypes.c_size_t
    k.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(_MBI), ctypes.c_size_t]
    k.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                    ctypes.POINTER(ctypes.c_size_t)]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k.OpenProcess(0x0410, False, pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if not h:
        log(f"cannot read the admin prompt (error {ctypes.get_last_error()})")
        return counts
    try:
        addr, total, mbi = 0, 0, _MBI()
        while total < 256 * 2**20 and k.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base, size = mbi.BaseAddress or 0, mbi.RegionSize
            if size == 0:
                break
            # committed memory that is not a program image and not no-access/guard pages
            if mbi.State == 0x1000 and mbi.Type != 0x1000000 and not (mbi.Protect & 0x101) and size <= 64 * 2**20:
                buf, got = ctypes.create_string_buffer(size), ctypes.c_size_t()
                if k.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(got)) and got.value:
                    total += got.value
                    paths_in(buf.raw[:got.value], counts)
            addr = base + size
    finally:
        k.CloseHandle(h)
    return counts


def rank_paths(counts):
    """Most likely program first: not a Windows system file, exists on disk, mentioned most often."""
    root = os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\"
    items = [(not p.lower().startswith(root), Path(p).is_file(), n, p) for p, n in counts.items()
             if PureWindowsPath(p).name.lower() not in _NOT_APPS]
    items.sort(reverse=True)
    return [x[3] for x in items]


def handle_uac_prompt(cpid):
    """A Windows administrator prompt (consent.exe) opened. If it belongs to a limited user: file a request."""
    cfg = jload(CFG, {})
    if not cfg.get("install_requests", True):
        return
    sid = proc_session(cpid)
    user = next((n for n, s_id, _ in sessions() if s_id == sid), None)
    admins = admin_names()
    if admins is None or not user or user in admins or not cfg.get("users", {}).get(user, {}).get("enabled"):
        return  # administrators (and unmanaged accounts) keep the normal Windows prompt
    ranked = rank_paths(scan_process_paths(cpid))
    cand, cmd = (ranked[0] if ranked else ""), ""
    if not cand:  # second chance: the process id in the prompt's command line, if it is a normal program
        cmd = proc_cmdline(cpid)
        m = re.search(r"consent(?:\.exe)?\"?\s+(\d+)", cmd, re.I)
        if m and int(m.group(1)) != cpid:
            pth = proc_path(int(m.group(1)))
            if pth and PureWindowsPath(pth).name.lower() not in _NOT_APPS:
                cand = pth
    if cfg.get("uac_block", True):
        run("taskkill", "/F", "/PID", str(cpid))  # closing the prompt = refusing the elevation
        try:  # tells that user's agent to close the "Incorrect function" error Windows then shows
            jsave(DATA / f"blocked_{re.sub(r'[^\w.-]', '_', user)}.json", {"ts": time.time(), "path": cand})
        except OSError:
            pass
    rid = auto_request(user, PureWindowsPath(cand).stem if cand else "", cand, "", file_sha256(cand) if cand else "")
    if rid:  # tell that user's agent to show "request sent to the administrator" - on EVERY attempt, even a repeated one
        try:
            jsave(DATA / f"notice_{re.sub(r'[^\w.-]', '_', user)}.json",
                  {"ts": time.time(), "id": rid, "program": clean_text(PureWindowsPath(cand).stem if cand else "", 80),
                   "blocked": bool(cfg.get("uac_block", True))})
        except OSError:
            pass
    log(f"admin prompt in {user}'s session -> request {rid}; program={cand or 'not detected'}; "
        f"found={ranked[:5]}; consent cmdline={cmd!r}")


def close_blocked_dialogs(path):
    """(agent) Close the error box Windows shows after a refused admin prompt: a dialog whose title is the program's
    own path (e.g. 'Incorrect function.'). `path` is the detected program; empty = any program path."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    user32.EnumWindows.argtypes = [enum_proc, wt.LPARAM]
    user32.IsWindowVisible.argtypes = [wt.HWND]
    user32.GetClassNameW.argtypes = user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    found = []

    def visit(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            cls, title = ctypes.create_unicode_buffer(32), ctypes.create_unicode_buffer(520)
            user32.GetClassNameW(hwnd, cls, 32)
            if cls.value == "#32770":  # standard dialog box
                user32.GetWindowTextW(hwnd, title, 520)
                if _EXE_PATH.fullmatch(title.value) and (not path or title.value.lower() == path.lower()):
                    found.append(hwnd)
        return True
    user32.EnumWindows(enum_proc(visit), 0)
    for h in found:
        user32.PostMessageW(h, 0x0111, 1, 0)  # WM_COMMAND / IDOK
        user32.PostMessageW(h, 0x0010, 0, 0)  # WM_CLOSE
    return len(found)


def uac_watch():
    seen = set()
    while not REMOVED.exists():
        try:
            procs = process_list()
            live = {p for p, _, _ in procs}
            for pid, _, exe in procs:
                if exe.lower() == "consent.exe" and pid not in seen:
                    seen.add(pid)
                    handle_uac_prompt(pid)
            seen &= live
        except Exception:
            log("admin-prompt watcher error: " + traceback.format_exc())
        time.sleep(0.5)


def engine_step(step, now):
    admins = admin_names()
    users = jload(CFG, {}).get("users", {})
    usage, status = jload(USE, {}), {}
    sync_accounts(users, admins)
    for name, sid, state in sessions():
        u = users.get(name)
        if admins is None or name in admins or not u or not u.get("enabled"):
            continue  # administrators are never limited
        if state == "active":
            ensure_agent(name, sid)
        ud = usage.setdefault(name, {})
        if state == "active":
            k, base = dt.date.today().isoformat(), total_used(ud)
            ud[k] = ud.get(k, 0) + step
            ud["_total"] = base + step
        rem = remaining(u, ud)
        used_today = ud.get(dt.date.today().isoformat(), 0)
        status[name] = {"remaining": -1 if rem is None else rem, "warn": u.get("warn", 5),
                        "ts": now,
                        "total": -1 if rem is None else used_today + max(rem, 0)}
        if rem is not None and rem <= 0:
            if u.get("action") == "lock":
                if state == "active":
                    run("tsdisconnect", str(sid))
            else:
                run("logoff", str(sid))
    jsave(USE, usage)
    jsave(STA, status)


def run_approved_launches():
    """(engine, SYSTEM) Start installers the administrator approved, inside the requesting user's own session.
    Only requests that the administrator approved (files only SYSTEM/administrators can write) are ever started."""
    for r in list_requests():
        L = r.get("launch")
        if r.get("status") != "approved" or not isinstance(L, dict) or L.get("state") != "queued":
            continue
        f = REQ / f"{r['id']}.json"

        def finish(state, note=None):
            cur = jload(f, None)
            if isinstance(cur, dict) and isinstance(cur.get("launch"), dict):
                cur["launch"]["state"] = state
                if note:
                    cur["note"] = clean_text(note, 200)
                jsave(f, cur)
            log(f"approved request {r['id']} ({r.get('user')}): {state} {note or ''}")
        path = str(L.get("path", ""))
        ext = Path(path).suffix.lower()
        if time.time() - L.get("ts", 0) > 3600:
            finish("failed", "It was approved, but the user was not signed in for an hour, so it was not started.")
            continue
        sid = next((i for n, i, st in sessions() if n == r.get("user") and st == "active"), None)
        if sid is None:
            continue  # wait until the user is signed in
        if path.lower().startswith(os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\"):
            finish("failed", "Windows’ own programs are never started this way.")
            continue
        if ext not in (".exe", ".msi") or not Path(path).is_file():
            finish("failed", "The installer file was not found.")
            continue
        if L.get("sha256") and file_sha256(path) != L["sha256"]:
            finish("failed", "The installer file changed after it was approved, so it was not started.")
            continue
        try:
            cmd = f'"{path}"' if ext == ".exe" else f'msiexec.exe /i "{path}"'
            launch_in_session(sid, cmd, str(Path(path).parent))
            finish("started")
        except Exception as e:
            finish("failed", f"It could not be started: {e}")


IDLE_SHUTDOWN_SECONDS = 5 * 60  # Settings > Login screen: how long the PC may sit at the sign-in screen
_idle = {"since": None, "sent": False, "left": None}


def idle_shutdown_step(now):
    """If enabled in Settings: shut the PC down once nobody has been signed in (it sits at the Windows sign-in screen) for 5 minutes.
    Any session - signed in, locked or disconnected - counts as 'somebody'. A shutdown that was already started is aborted if a user signs in during its short countdown.
    _idle["left"] = seconds until that shutdown (None when the countdown is not running); the sign-in-screen widget shows it."""
    _idle["left"] = None
    _idle["why"] = None
    if not jload(CFG, {}).get("idle_shutdown", False):
        _idle["why"] = "The 5-minute shutdown at the sign-in screen is switched off (WoL Host > TimeGuard > Settings)"
        if _idle["sent"]:
            run("shutdown", "/a")
        _idle["since"], _idle["sent"] = None, False
        return
    if sessions():
        if _idle["sent"]:
            run("shutdown", "/a")  # somebody signed in during the 30 s countdown
            log("login-screen shutdown aborted: a user signed in")
        _idle["since"], _idle["sent"] = None, False
        return
    if _idle["since"] is None:
        _idle["since"] = now
    elif not _idle["sent"] and now - _idle["since"] >= IDLE_SHUTDOWN_SECONDS:
        _idle["sent"] = True
        log("nobody signed in for 5 minutes - shutting the PC down")
        run("shutdown", "/s", "/t", "30", "/c", "TimeGuard: nobody signed in for 5 minutes. The PC shuts down in 30 seconds.")
    _idle["left"] = 0.0 if _idle["sent"] else max(IDLE_SHUTDOWN_SECONDS - (now - _idle["since"]), 0.0)
    ensure_idle_widget(None, None)


AUTO_LOGOFF_SECONDS = 15 * 60   # Accounts > per-user setting: signed-in users with no keyboard / mouse / game-controller input for this long are signed out
AUTO_LOGOFF_WARN = 60           # ... after a warning message this many seconds before
_warned = {}                    # session id -> True once the warning was sent (cleared as soon as the user is active again)


class _WTSINFO(ctypes.Structure):  # WTSINFOW (WTSSessionInfo = 24); the FILETIME values are 100 ns ticks
    _fields_ = [("State", ctypes.c_int), ("SessionId", ctypes.c_uint32), ("InB", ctypes.c_uint32), ("OutB", ctypes.c_uint32),
                ("InF", ctypes.c_uint32), ("OutF", ctypes.c_uint32), ("InCB", ctypes.c_uint32), ("OutCB", ctypes.c_uint32),
                ("WinStation", ctypes.c_wchar * 32), ("Domain", ctypes.c_wchar * 17), ("User", ctypes.c_wchar * 20),
                ("ConnectTime", ctypes.c_int64), ("DisconnectTime", ctypes.c_int64), ("LastInputTime", ctypes.c_int64),
                ("LogonTime", ctypes.c_int64), ("CurrentTime", ctypes.c_int64)]


def session_idle_seconds(sid):
    """Seconds since the last keyboard / mouse input in a session (works from the SYSTEM service). None when Windows gives no usable value -
    then nobody is ever signed out because of it."""
    wts = ctypes.WinDLL("wtsapi32")
    buf, n = ctypes.c_void_p(), ctypes.c_uint32()
    wts.WTSQuerySessionInformationW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
    if not wts.WTSQuerySessionInformationW(None, int(sid), 24, ctypes.byref(buf), ctypes.byref(n)) or not buf.value:
        return None
    try:
        info = ctypes.cast(buf, ctypes.POINTER(_WTSINFO)).contents
        last = info.LastInputTime
        if info.State == 4:  # disconnected: the idle time starts when it was disconnected, if that is later
            last = max(last, info.DisconnectTime)
        if last <= 0 or info.CurrentTime <= last:
            return None
        idle = (info.CurrentTime - last) / 1e7
        return idle if idle < 30 * 86400 else None
    finally:
        wts.WTSFreeMemory(buf)


PAD_POLL = 1.0  # seconds between controller polls in the per-session watcher


def pad_file(sid):
    return DATA / f"pad_{int(sid)}.txt"


def input_file(sid):
    return DATA / f"input_{int(sid)}.txt"


def input_idle_seconds(sid, now):
    """Seconds since the last keyboard / mouse input as seen INSIDE the session (GetLastInputInfo, written once a second by the per-session watcher; it also
    counts injected input such as Sunshine's). None = watcher not running / no value. A stale file (watcher gone) is never used."""
    try:
        hb, ts = (float(x) for x in input_file(sid).read_text("utf-8").split()[:2])
    except (OSError, ValueError):
        return None
    if now - hb > 10:
        return None
    d = now - ts
    return d if d >= 0 else 0.0


def session_logon_seconds(sid):
    """Seconds since this session was created (the user signed in). None when Windows gives no value."""
    wts = ctypes.WinDLL("wtsapi32")
    buf, n = ctypes.c_void_p(), ctypes.c_uint32()
    wts.WTSQuerySessionInformationW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
    if not wts.WTSQuerySessionInformationW(None, int(sid), 24, ctypes.byref(buf), ctypes.byref(n)) or not buf.value:
        return None
    try:
        info = ctypes.cast(buf, ctypes.POINTER(_WTSINFO)).contents
        if info.LogonTime <= 0 or info.CurrentTime <= info.LogonTime:
            return None
        return (info.CurrentTime - info.LogonTime) / 1e7
    finally:
        wts.WTSFreeMemory(buf)


def pad_idle_seconds(sid, now):
    """Seconds since the per-session watcher last saw game-controller / joystick input. None = never seen (or watcher not running)."""
    try:
        ts = float(pad_file(sid).read_text("utf-8").strip())
    except (OSError, ValueError):
        return None
    d = now - ts
    return d if d >= 0 else 0.0  # a clock that moved back counts as 'just now'


_pad_launched = {}


def ensure_pad_watcher(sid):
    """(SYSTEM) Keep the controller watcher running in this session. The engine itself lives in session 0 and cannot see controllers."""
    if not may_launch(("pad", sid), _mutex_alive(f"Global\\TimeGuardPad-{sid}")):
        return
    base = [sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)])
    try:
        launch_in_session(sid, " ".join(f'"{x}"' for x in base) + " --tg-pad")
    except Exception as e:
        log(f"could not start the controller watcher (session {sid}): {e}")


def _mutex_alive(name):
    try:
        import ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenMutexW.restype = ctypes.c_void_p
        k.OpenMutexW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k.OpenMutexW(0x00100000, 0, name)  # SYNCHRONIZE
        if h:
            k.CloseHandle(h)
            return True
    except Exception:
        pass
    return False


def run_pad():
    """--tg-pad: tiny stdlib-only process, one per session, running as SYSTEM on the user's desktop. Polls XInput pads (Xbox / Sunshine virtual
    pads) and winmm joysticks; whenever one is being used it writes the time to DATA/pad_<session>.txt, which auto_logoff_step reads."""
    import ctypes
    from ctypes import wintypes as wt
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateMutexW.restype = ctypes.c_void_p
    k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    sess = ctypes.c_uint32()
    k.ProcessIdToSessionId(os.getpid(), ctypes.byref(sess))
    mutex = k.CreateMutexW(None, 0, f"Global\\TimeGuardPad-{sess.value}")
    if mutex and ctypes.get_last_error() == 183:  # already running in this session
        return

    class XPAD(ctypes.Structure):
        _fields_ = [("buttons", wt.WORD), ("lt", ctypes.c_ubyte), ("rt", ctypes.c_ubyte), ("lx", ctypes.c_short),
                    ("ly", ctypes.c_short), ("rx", ctypes.c_short), ("ry", ctypes.c_short)]

    class XSTATE(ctypes.Structure):
        _fields_ = [("packet", wt.DWORD), ("pad", XPAD)]

    xget = None
    for dll in ("xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"):
        try:
            xget = ctypes.WinDLL(dll).XInputGetState
            xget.argtypes = [wt.DWORD, ctypes.POINTER(XSTATE)]
            break
        except (OSError, AttributeError):
            continue

    class JOYEX(ctypes.Structure):
        _fields_ = [(n, wt.DWORD) for n in ("size", "flags", "x", "y", "z", "r", "u", "v", "buttons", "button_n", "pov", "r1", "r2")]

    try:
        jget = ctypes.WinDLL("winmm").joyGetPosEx
        jget.argtypes = [wt.UINT, ctypes.POINTER(JOYEX)]
    except (OSError, AttributeError):
        jget = None

    def xinput_active():
        if not xget:
            return False
        for i in range(4):
            st = XSTATE()
            if xget(i, ctypes.byref(st)) != 0:  # 0 = connected
                continue
            g = st.pad
            if (g.buttons or g.lt > 30 or g.rt > 30 or abs(g.lx) > 7849 or abs(g.ly) > 7849  # XInput's own dead zones
                    or abs(g.rx) > 8689 or abs(g.ry) > 8689):
                return True
        return False

    base, prev = {}, {}  # joystick id -> first / previous axis values (axes that rest off-centre must not count as activity)

    def joy_active():
        if not jget:
            return False
        hit, seen = False, set()
        for i in range(16):
            ji = JOYEX()
            ji.size, ji.flags = ctypes.sizeof(JOYEX), 0xFF  # JOY_RETURNALL
            if jget(i, ctypes.byref(ji)) != 0:
                base.pop(i, None)
                prev.pop(i, None)
                continue
            seen.add(i)
            axes = (ji.x, ji.y, ji.z, ji.r, ji.u, ji.v)
            if i not in base:
                base[i] = axes
            moved = any(abs(a - b) > 0x0800 for a, b in zip(axes, prev.get(i, axes)))
            off = any(abs(a - b) > 0x3333 for a, b in zip(axes, base[i]))
            prev[i] = axes
            if ji.buttons or ji.pov not in (0xFFFF, 0xFFFFFFFF) or moved or off:
                hit = True
        return hit

    class LII(ctypes.Structure):
        _fields_ = [("cbSize", wt.UINT), ("dwTime", wt.DWORD)]

    try:
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k.GetTickCount.restype = wt.DWORD
    except OSError:
        u32 = None

    def last_input_ts():
        """Wall-clock time of the last keyboard / mouse input in THIS session (None if Windows has none)."""
        if not u32:
            return None
        li = LII()
        li.cbSize = ctypes.sizeof(LII)
        if not u32.GetLastInputInfo(ctypes.byref(li)) or not li.dwTime:
            return None
        return time.time() - ((k.GetTickCount() - li.dwTime) & 0xFFFFFFFF) / 1000.0

    me = sess.value
    tick = 0
    while True:  # the engine only starts this for accounts that have the inactivity sign-out on
        if REMOVED.exists():
            return
        try:
            if xinput_active() or joy_active():
                pad_file(me).write_text(str(time.time()), "utf-8")
        except Exception:
            pass
        try:
            tick += 1
            if tick % 2 == 0:  # every 2 s: "heartbeat last-input-time" for the engine
                ts = last_input_ts()
                if ts is not None:
                    input_file(me).write_text(f"{time.time()} {ts}", "utf-8")
        except Exception:
            pass
        time.sleep(PAD_POLL)


IDLE_WIDGET_SHOW_AFTER = 0  # seconds of inactivity before a signed-in user's widget appears (0 = always visible while the setting is on)
IDLE_FILE = DATA / "inactive.json"   # engine -> widgets: {"ts", "login": seconds|None, "sessions": {sid: seconds left before sign-out}}
_idle_launched = {}
_idle_why = {}


def console_session():
    try:
        import ctypes
        n = ctypes.WinDLL("kernel32").WTSGetActiveConsoleSessionId()
        return None if n == 0xFFFFFFFF else int(n)  # 0xFFFFFFFF = no console session
    except Exception:
        return None


def ensure_idle_widget(user, sid):
    """Keep the small inactivity widget running: in a user's session (user, sid), or - with (None, None) - on the Windows sign-in screen."""
    return  # the countdown widgets are gone: the engine still counts, and WoL Remote shows the time (Login user tab: shutdown at the sign-in screen, Stream tab: inactivity sign-out)
    login = user is None
    if login:
        sid = console_session()
        if sid is None or sid > 1000000:
            return
    key = ("login", sid) if login else ("user", sid)
    if _mutex_alive(f"Global\\TimeGuardIdle{'Login' if login else 'User'}-{sid}") or time.time() - _idle_launched.get(key, 0) < 10:
        return
    _idle_launched[key] = time.time()
    log(f"starting the inactivity widget ({'sign-in screen' if login else user}, session {sid})")
    base = [sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)])
    cmd = " ".join(f'"{x}"' for x in base) + (" --tg-idle --login" if login else f' --tg-idle --user "{user}"')
    try:
        launch_in_session(sid, cmd, desktop="winsta0\\winlogon" if login else "winsta0\\default")
    except Exception as e:
        log(f"could not start the inactivity widget ({'sign-in screen' if login else user}, session {sid}): {e}")


def write_idle_status(now, left_by_sid, left_by_name=None, why_by_name=None):
    try:
        jsave(IDLE_FILE, {"ts": now, "login": _idle.get("left"), "sessions": {str(k): v for k, v in left_by_sid.items()}, "users": left_by_name or {},
                          "why": {"login": _idle.get("why"), "users": why_by_name or {}}})
    except OSError:
        pass


def auto_logoff_step(now):
    """For every NON-administrator account whose own setting (Accounts page) is on: warn, then sign out after 15 minutes without keyboard / mouse /
    game-controller input (signed-in, locked or disconnected). Administrator accounts are never signed out (and get no countdown widget)."""
    cfg = jload(CFG, {})
    admins = admin_names()
    left_by_sid, left_by_name, why_by_name = {}, {}, {}
    if admins is None:  # could not tell who is an administrator -> sign nobody out
        write_idle_status(now, {})
        return
    live = set()
    for name, sid, state in sessions():
        live.add(sid)
        if name in admins or not user_auto_logoff(cfg, name):  # administrators and accounts with the setting off are never signed out
            _warned.pop(sid, None)
            _why = "administrator accounts get no inactivity widget" if name in admins else "'Sign out after 15 minutes of inactivity' is off for this account (Accounts page; 'Manage' must be on too)"
            why_by_name[name] = _why
            if _idle_why.get(sid) != _why:
                _idle_why[sid] = _why
                log(f"no inactivity widget for {name} (session {sid}): {_why}")
            continue
        _idle_why.pop(sid, None)
        if state == "active":
            ensure_pad_watcher(sid)
            ensure_idle_widget(name, sid)
        idle = session_idle_seconds(sid)
        alt = input_idle_seconds(sid, now)  # the same thing measured inside the session: also works when Windows' own session value stays empty after a remote sign-in
        if alt is not None:
            idle = alt if idle is None else min(idle, alt)
        try:
            since = session_logon_seconds(sid)  # a session cannot have been idle for longer than it has existed
        except Exception:
            since = None
        if idle is None:
            if since is None:
                left_by_sid[sid] = left_by_name[name] = -1.0  # unknown: shown as --:-- (nobody is signed out without a real idle value)
            else:  # no input value yet: show a countdown from the sign-in, but never act on an estimate
                left_by_sid[sid] = left_by_name[name] = max(AUTO_LOGOFF_SECONDS - since, AUTO_LOGOFF_WARN + 60.0)
            continue
        if since is not None:
            idle = min(idle, since)
        pad = pad_idle_seconds(sid, now)  # a game controller / joystick counts as input too
        if pad is not None:
            idle = min(idle, pad)
        left_by_sid[sid] = left_by_name[name] = max(AUTO_LOGOFF_SECONDS - idle, 0.0)
        if idle < AUTO_LOGOFF_SECONDS - AUTO_LOGOFF_WARN:
            _warned.pop(sid, None)
            continue
        if idle < AUTO_LOGOFF_SECONDS:
            if not _warned.get(sid) and state == "active":
                _warned[sid] = True
                run("msg", str(sid), "/time:60", "TimeGuard: no activity for a while. You will be signed out in about a minute - move the mouse or press a key to stay signed in.")
            continue
        log(f"{name} (session {sid}) idle for {int(idle // 60)} minutes - signing out")
        _warned.pop(sid, None)
        run("logoff", str(sid))
    for sid in list(_warned):
        if sid not in live:
            del _warned[sid]
    write_idle_status(now, left_by_sid, left_by_name, why_by_name)


# ---------------- Drive restriction (Accounts > <user> > Manage > "Restrict access to specific drives") ----------------
DRIVES_FILE = DATA / "drives_applied.json"   # {user: bitmask we wrote}, so only OUR policy values are ever removed again
_drv = {"t": 0.0, "sid": {}, "last": {}}
_POL = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"


def drive_mask(letters):
    """Drive letters -> the bitmask Windows policies use (A = 1, B = 2, C = 4 ...)."""
    m = 0
    for c in letters or []:
        c = str(c).upper()
        if len(c) == 1 and "A" <= c <= "Z":
            m |= 1 << (ord(c) - 65)
    return m


def user_sid(name):
    if name not in _drv["sid"]:
        r = run("powershell", "-NoProfile", "-Command",
                f"(New-Object System.Security.Principal.NTAccount('{name.replace(chr(39), '')}')).Translate([System.Security.Principal.SecurityIdentifier]).Value")
        s = r.stdout.strip()
        if not s.startswith("S-1-"):
            return None
        _drv["sid"][name] = s
    return _drv["sid"][name]


def block_mask(letters):
    """Drives that are really BLOCKED: every ticked drive except the Windows drive. That one is only hidden, because blocking it would
    also block the Desktop, Documents and the programs' own folders (they all live on it)."""
    sysd = os.environ.get("SystemDrive", "C:")[:1].upper()
    return drive_mask([c for c in (letters or []) if str(c).upper() != sysd])


def set_drive_policy(name, mask, block=None):
    """(SYSTEM) Write / remove NoDrives + NoViewOnDrive in the user's registry: in the loaded hive when they are signed in, otherwise by loading NTUSER.DAT.
    NoDrives (mask) hides the drives in File Explorer; NoViewOnDrive (block, default = mask) stops Explorer and Open/Save dialogs from opening them. Returns True when done."""
    block = mask if block is None else block
    sid = user_sid(name)
    if not sid:
        return False
    loaded = None
    if run("reg", "query", f"HKU\\{sid}").returncode == 0:
        hive = f"HKU\\{sid}"
    else:
        r = run("reg", "query", rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", "/v", "ProfileImagePath")
        m = re.search(r"REG_\w+\s+(.+)", r.stdout)
        dat = Path(os.path.expandvars(m.group(1).strip())) / "NTUSER.DAT" if m else None
        if not dat or not dat.exists():
            return False
        loaded = "TG_drives"
        run("reg", "unload", f"HKU\\{loaded}")  # a leftover from an earlier crash
        if run("reg", "load", f"HKU\\{loaded}", str(dat)).returncode != 0:
            return False
        hive = f"HKU\\{loaded}"
    key = hive + "\\" + _POL
    try:
        for val, m in (("NoDrives", mask), ("NoViewOnDrive", block)):
            if m:
                if run("reg", "add", key, "/v", val, "/t", "REG_DWORD", "/d", str(m), "/f").returncode != 0:
                    return False
            else:
                run("reg", "delete", key, "/v", val, "/f")  # fails harmlessly when it is not there
        return True
    finally:
        if loaded:
            for _ in range(5):
                if run("reg", "unload", f"HKU\\{loaded}").returncode == 0:
                    break
                time.sleep(0.5)


def drive_policy_step(now):
    """Keep every managed, non-administrator user's blocked drives in line with the Accounts page (re-applied every 2 minutes, so it cannot be undone for long)."""
    if now - _drv["t"] < 15:
        return
    _drv["t"] = now
    admins = admin_names()
    if admins is None:
        return
    users = jload(CFG, {}).get("users", {})
    applied = jload(DRIVES_FILE, {})
    for name in set(users) | set(applied):
        u = users.get(name) or {}
        off = not u.get("enabled") or not u.get("restrict_drives") or name in admins
        want = 0 if off else drive_mask(u.get("block_drives", []))
        had = applied.get(name, 0)
        if want == had and (want == 0 or now - _drv["last"].get(name, 0) < 120):
            continue
        _drv["last"][name] = now
        if set_drive_policy(name, want, 0 if off else block_mask(u.get("block_drives", []))):
            if want != had:
                log(f"drive restriction for {name}: {'blocked mask %d' % want if want else 'removed'}")
            if want:
                applied[name] = want
            else:
                applied.pop(name, None)
            try:
                jsave(DRIVES_FILE, applied)
            except OSError:
                pass


# ---------------- Windows password lock: standard users can never set or change their own Windows password ----------------
# Runs by itself inside the engine (no button, no setting) for as long as the TimeGuard service runs. Why: a standard user who sets a password on an
# account that has none (the remote-PIN accounts) or changes the one it has would break remote sign-in and get around the PIN.
#  * the account flag "User may change password" is switched off (net user NAME /passwordchg:no): Windows itself then refuses Settings, Ctrl+Alt+Del
#    and `net user NAME *`. Administrators (and this engine) can still reset a password - that is not blocked by the flag.
#  * DisableChangePassword = 1 in the user's own registry hides "Change a password" in Ctrl+Alt+Del / Settings as well.
# Re-checked every 30 s, so undoing it lasts at most half a minute. Administrator accounts are never touched. Only locks made here are ever lifted.
PWLOCK_FILE = DATA / "pwlock_applied.json"   # {user: {"flag": True if WE switched the account flag off}}
_pwl = {"t": 0.0, "reg": {}}
_SYSPOL = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"


def set_user_pw_policy(name, on):
    """(SYSTEM) Write / remove DisableChangePassword in the user's registry: in the loaded hive when they are signed in, otherwise by loading NTUSER.DAT."""
    sid = user_sid(name)
    if not sid:
        return False
    loaded = None
    if run("reg", "query", f"HKU\\{sid}").returncode == 0:
        hive = f"HKU\\{sid}"
    else:
        r = run("reg", "query", rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", "/v", "ProfileImagePath")
        m = re.search(r"REG_\w+\s+(.+)", r.stdout)
        dat = Path(os.path.expandvars(m.group(1).strip())) / "NTUSER.DAT" if m else None
        if not dat or not dat.exists():
            return False
        loaded = "TG_pwlock"
        run("reg", "unload", f"HKU\\{loaded}")  # a leftover from an earlier crash
        if run("reg", "load", f"HKU\\{loaded}", str(dat)).returncode != 0:
            return False
        hive = f"HKU\\{loaded}"
    key = hive + "\\" + _SYSPOL
    try:
        if on:
            return run("reg", "add", key, "/v", "DisableChangePassword", "/t", "REG_DWORD", "/d", "1", "/f").returncode == 0
        run("reg", "delete", key, "/v", "DisableChangePassword", "/f")  # fails harmlessly when it is not there
        return True
    finally:
        if loaded:
            for _ in range(5):
                if run("reg", "unload", f"HKU\\{loaded}").returncode == 0:
                    break
                time.sleep(0.5)


def password_lock_step(now, lift_all=False):
    """Keep every enabled, local, non-administrator account unable to set or change its own Windows password (see the block comment above).
    lift_all=True (protection removed): give every account we locked its normal rights back."""
    if not lift_all and now - _pwl["t"] < 30:
        return
    _pwl["t"] = now
    admins = admin_names()
    if admins is None:  # could not tell who is an administrator -> lock nobody
        return
    ps = ("Get-LocalUser | Where-Object { $_.Enabled -and $_.PrincipalSource -eq 'Local' } | "
          "ForEach-Object { $_.Name + '|' + [int]$_.UserMayChangePassword }")
    r = run("powershell", "-NoProfile", "-Command", ps)
    seen = {}
    for line in (r.stdout or "").splitlines():
        parts = line.strip().rsplit("|", 1)
        if len(parts) == 2 and parts[1] in ("0", "1"):
            seen[parts[0]] = parts[1] == "1"
    if r.returncode != 0 or not seen:
        return
    applied, changed = jload(PWLOCK_FILE, {}), False
    for name, may in seen.items():
        if lift_all or name.lower() in admins:
            got = applied.pop(name, None)
            if got is not None:  # an account we locked: give it back (it became an administrator, or the protection was removed)
                if got.get("flag"):
                    run("net", "user", name, "/passwordchg:yes")
                set_user_pw_policy(name, False)
                _pwl["reg"].pop(name, None)
                changed = True
                log(f"password lock lifted for {name}")
            continue
        if may:
            if run("net", "user", name, "/passwordchg:no").returncode == 0:
                applied[name] = {"flag": True}
                changed = True
                log(f"password lock: {name} can no longer set or change their Windows password")
        elif name not in applied:
            applied[name] = {"flag": False}  # the account flag was already off (not our doing): keep it that way when we lift
            changed = True
        if now - _pwl["reg"].get(name, 0) > 120:
            _pwl["reg"][name] = now
            set_user_pw_policy(name, True)
    if changed:
        try:
            jsave(PWLOCK_FILE, applied)
        except OSError:
            pass


def run_engine():
    DATA.mkdir(parents=True, exist_ok=True)
    log("engine started")
    threading.Thread(target=uac_watch, daemon=True).start()
    last = time.time()
    while True:
        if REMOVED.exists():
            try:
                password_lock_step(time.time(), lift_all=True)
            except Exception:
                log("password lock lift error: " + traceback.format_exc())
            return
        time.sleep(5)
        if REMOVED.exists():
            try:
                password_lock_step(time.time(), lift_all=True)
            except Exception:
                log("password lock lift error: " + traceback.format_exc())
            return
        now = time.time()
        step, last = min(now - last, 30), now
        try:
            engine_step(step, now)
        except Exception:  # one bad round must never stop the protection; the reason is written to engine.log
            log("engine error: " + traceback.format_exc())
        try:
            run_approved_launches()
        except Exception:
            log("launch error: " + traceback.format_exc())
        try:
            idle_shutdown_step(now)
        except Exception:
            log("idle shutdown error: " + traceback.format_exc())
        try:
            auto_logoff_step(now)
        except Exception:
            log("auto log-off error: " + traceback.format_exc())
        try:
            drive_policy_step(now)
        except Exception:
            log("drive restriction error: " + traceback.format_exc())
        try:
            password_lock_step(now)
        except Exception:
            log("password lock error: " + traceback.format_exc())


if "--tg-pad" in sys.argv:
    run_pad()
    sys.exit(0)


if "--tg-engine" in sys.argv or (__name__ == "__main__" and "--engine" in sys.argv):
    run_engine()
    sys.exit(0)

# ───────────────────────── Qt (GUI + agent) ─────────────────────────
from PySide6.QtCore import (Qt, QTimer, QTime, QRectF, QRect, QSize, QPoint, QEasingCurve, QVariantAnimation,
                            QPropertyAnimation, QAbstractAnimation, QLockFile, QThread, Signal, QObject, QBuffer, QIODevice,
                            QRegularExpression)
from PySide6.QtGui import (QIcon, QPixmap, QPainter, QColor, QPen, QBrush, QValidator, QFont,
                           QLinearGradient, QAction, QImage, QPainterPath, QRegularExpressionValidator)
from PySide6.QtNetwork import (QTcpServer, QTcpSocket, QHostAddress, QAbstractSocket, QLocalServer, QLocalSocket)
from PySide6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QFrame, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QGridLayout, QStackedWidget, QListWidget, QSpinBox, QCheckBox, QTimeEdit, QComboBox,
    QProgressBar, QScrollArea, QMessageBox, QInputDialog, QLineEdit, QSystemTrayIcon, QFileDialog,
    QGraphicsOpacityEffect, QMenu, QListWidgetItem, QDialog, QSizePolicy, QWidgetAction)

QSS = """
QWidget{background:#12141A;color:#E6E8EF;font-family:'Segoe UI';font-size:10.5pt}
QLabel,QCheckBox{background:transparent}
#side{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #171B28,stop:1 #0E1016)}
#title{font-size:17pt;font-weight:600}
#h1{font-size:22pt;font-weight:700}
#h2{font-size:13pt;font-weight:600}
#big{font-size:20pt;font-weight:700}
#muted{color:#8A90A2}
QPushButton{background:#232733;border:1px solid #2B3043;border-radius:9px;padding:8px 14px}
QPushButton:hover{background:#2D3448;border-color:#44507A}
QPushButton:pressed{background:#1D2130}
QPushButton#primary{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #6C8CFF,stop:1 #9B7CFF);color:#0B0D12;font-weight:600;border:none}
QPushButton#primary:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #86A0FF,stop:1 #B093FF)}
QPushButton#danger{background:#3A2227;color:#FF8A9A;border-color:#4C2A31}
QPushButton#danger:hover{background:#4A2A31}
QPushButton#nav{text-align:left;background:transparent;border:none;border-left:3px solid transparent;border-radius:0;padding:12px 14px;font-size:11pt}
QPushButton#nav:hover{background:#1B1F2C}
QPushButton#nav:checked{background:#1F2433;color:#fff;font-weight:600}
QFrame#card,QFrame#tile{background:#1A1D27;border:1px solid #262B3A;border-radius:16px}
QSpinBox,QTimeEdit,QComboBox,QLineEdit{background:#232733;border:1px solid #2D3345;border-radius:7px;padding:5px 8px;min-width:110px}
QSpinBox:focus,QTimeEdit:focus,QComboBox:focus,QLineEdit:focus{border-color:#6C8CFF}
QListWidget{background:#1A1D27;border:none;border-radius:12px;padding:6px;outline:0}
QListWidget::item{padding:10px;border-radius:8px}
QListWidget::item:hover{background:#222636}
QListWidget::item:selected{background:#2D3345;color:#fff}
QScrollArea{border:none}
QWidget#body{background:transparent}
QLabel#screen{background:#0E1016;border-radius:10px;color:#8A90A2}
QFrame#card:hover{border-color:#343B54}
QSpinBox:disabled,QTimeEdit:disabled,QComboBox:disabled{color:#5A6074;background:#1B1E29;border-color:#232735}
QPushButton:disabled{color:#5A6074;background:#1B1E29;border-color:#232735}
QListWidget:disabled{color:#5A6074}
QScrollBar:vertical{background:transparent;width:8px}
QScrollBar::handle:vertical{background:#2D3345;border-radius:4px}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}
"""


def fade_in(w, delay=0, dur=320):
    """Fade a widget in (and drop the effect afterwards so it renders normally)."""
    eff = QGraphicsOpacityEffect(w)
    eff.setOpacity(0.0)
    w.setGraphicsEffect(eff)
    a = QPropertyAnimation(eff, b"opacity", w)
    a.setDuration(dur)
    a.setStartValue(0.0)
    a.setEndValue(1.0)
    a.setEasingCurve(QEasingCurve.OutCubic)
    a.finished.connect(lambda: w.setGraphicsEffect(None))

    def go():
        try:
            a.start()
        except RuntimeError:  # widget was deleted meanwhile
            pass
    QTimer.singleShot(delay, go)


class AnimBar(QWidget):
    """Slim rounded progress bar with a smooth value animation; turns amber/red when nearly full."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(10)
        self._v, self._t = 0.0, 0.0
        self._a = QVariantAnimation(self)
        self._a.setDuration(750)
        self._a.setEasingCurve(QEasingCurve.OutCubic)
        self._a.valueChanged.connect(self._set)

    def _set(self, v):
        self._v = v
        self.update()

    def set_value(self, f):
        f = max(0.0, min(1.0, f))
        if abs(f - self._t) < 0.002:
            return
        self._t = f
        self._a.stop()
        self._a.setStartValue(self._v)
        self._a.setEndValue(f)
        self._a.start()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect())
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#232733"))
        p.drawRoundedRect(r, 5, 5)
        if self._v > 0:
            c1, c2 = (("#6C8CFF", "#9B7CFF") if self._v < 0.8 else
                      ("#FFB347", "#FF8A4C") if self._v < 0.95 else ("#FF6B81", "#FF4D6D"))
            g = QLinearGradient(0, 0, r.width(), 0)
            g.setColorAt(0, QColor(c1))
            g.setColorAt(1, QColor(c2))
            p.setBrush(QBrush(g))
            p.drawRoundedRect(QRectF(0, 0, max(10.0, r.width() * self._v), r.height()), 5, 5)


class StatTile(QFrame):
    """Small dashboard tile whose number counts up/down smoothly."""

    def __init__(self, title, fmtfn=str):
        super().__init__()
        self.setObjectName("tile")
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 14)
        v.setSpacing(2)
        t = QLabel(title)
        t.setObjectName("muted")
        self.val = QLabel("–")
        self.val.setObjectName("big")
        v.addWidget(t)
        v.addWidget(self.val)
        self._f, self._cur, self._tgt = fmtfn, 0.0, None
        self._a = QVariantAnimation(self)
        self._a.setDuration(800)
        self._a.setEasingCurve(QEasingCurve.OutCubic)
        self._a.valueChanged.connect(self._step)

    def _step(self, x):
        self._cur = x
        self.val.setText(self._f(x))

    def animate_to(self, x):
        if x == self._tgt:
            return
        self._tgt = x
        self._a.stop()
        self._a.setStartValue(float(self._cur))
        self._a.setEndValue(float(x))
        self._a.start()

    def set_text(self, text, color=""):
        self.val.setText(text)
        self.val.setStyleSheet(f"color:{color}" if color else "")


class Toggle(QCheckBox):
    """Animated on/off switch."""

    def __init__(self, text=""):
        super().__init__(text)
        self.setCursor(Qt.PointingHandCursor)
        self._x = 0.0
        self._a = QVariantAnimation(self)
        self._a.setDuration(180)
        self._a.setEasingCurve(QEasingCurve.InOutCubic)
        self._a.valueChanged.connect(self._set)
        self.toggled.connect(self._go)

    def _set(self, v):
        self._x = v
        self.update()

    def _go(self, on):
        self._a.stop()
        self._a.setStartValue(self._x)
        self._a.setEndValue(1.0 if on else 0.0)
        self._a.start()

    def sizeHint(self):
        return QSize(56 + self.fontMetrics().horizontalAdvance(self.text()), 30)

    def minimumSizeHint(self):
        return self.sizeHint()

    def hitButton(self, pos):
        return self.rect().contains(pos)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        off, on, x = QColor("#2D3345"), QColor("#6C8CFF"), self._x
        c = QColor(int(off.red() + (on.red() - off.red()) * x), int(off.green() + (on.green() - off.green()) * x),
                   int(off.blue() + (on.blue() - off.blue()) * x))
        ok = self.isEnabled()
        if not ok:
            c.setAlpha(110)
        p.setPen(Qt.NoPen)
        p.setBrush(c)
        p.drawRoundedRect(QRectF(1, 3, 42, 24), 12, 12)
        p.setBrush(QColor("#FFFFFF") if ok else QColor("#9AA0B2"))
        p.drawEllipse(QRectF(5 + 18 * x, 7, 16, 16))
        p.setPen(QColor("#E6E8EF") if ok else QColor("#5A6074"))
        p.setFont(self.font())
        p.drawText(QRectF(56, 0, self.width() - 56, self.height()), Qt.AlignVCenter | Qt.AlignLeft, self.text())


class TimeWidget(QWidget):
    """Always-on-top countdown for the limited user: movable, but it cannot be closed or dragged off-screen."""
    W, H = 300, 112

    def __init__(self):
        super().__init__(None, Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.WindowDoesNotAcceptFocus | Qt.WindowTransparentForInput)      # click-through: mouse clicks go to the window UNDER it, so it can never take the focus away from the stream
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setFixedSize(self.W, self.H)
        self.rem, self.total, self.warn, self.ts = None, 0.0, 5, time.time()
        self._intro, self._pulse = 0.0, 0.0
        self._placed = False
        self.waiting = True  # until the first status arrives
        self._drag = None
        self._ia = QVariantAnimation(self)
        self._ia.setDuration(1100)
        self._ia.setStartValue(0.0)
        self._ia.setEndValue(1.0)
        self._ia.setEasingCurve(QEasingCurve.OutCubic)
        self._ia.valueChanged.connect(self._set_intro)
        self._pa = QVariantAnimation(self)
        self._pa.setDuration(1100)
        self._pa.setStartValue(0.0)
        self._pa.setEndValue(1.0)
        self._pa.setLoopCount(-1)
        self._pa.valueChanged.connect(self._set_pulse)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._second)
        self._timer.start(1000)

    def _set_intro(self, v):
        self._intro = v
        self.update()

    def _set_pulse(self, v):
        self._pulse = v
        self.update()

    def current(self):
        return None if self.rem is None else max(self.rem - (time.time() - self.ts), 0.0)

    def update_status(self, rem, total, warn, ts):
        self.rem = None if rem < 0 else float(rem)
        self.total = float(total) if total > 0 else 0.0
        self.warn, self.ts = warn, ts or time.time()
        self.waiting = False
        self._second()

    def _second(self):
        cur = self.current()
        crit = cur is not None and cur <= 60
        running = self._pa.state() == QAbstractAnimation.State.Running
        if crit and not running:
            self._pa.start()
        elif not crit and running:
            self._pa.stop()
            self._pulse = 0.0
        if self.isVisible():
            self._pin()
        self.update()

    def _pin(self):
        """Keep the window above every other window (including other always-on-top ones)."""
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes
            f = ctypes.windll.user32.SetWindowPos
            f.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                          ctypes.c_int, wintypes.UINT]
            # This widget runs as SYSTEM inside the user's session. It must NEVER become the active window: keyboard / mouse input that Sunshine (Moonlight)
            # injects as the normal user is dropped by Windows (UIPI) while a SYSTEM window has the focus - the stream would show but not react.
            gl, sl = ctypes.windll.user32.GetWindowLongPtrW, ctypes.windll.user32.SetWindowLongPtrW
            gl.restype = sl.restype = ctypes.c_ssize_t
            gl.argtypes = [wintypes.HWND, ctypes.c_int]
            sl.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
            hw = wintypes.HWND(int(self.winId()))
            ex = gl(hw, -20)  # GWL_EXSTYLE
            if not ex & 0x08000000:
                sl(hw, -20, ex | 0x08000000 | 0x80 | 0x20 | 0x80000)  # WS_EX_NOACTIVATE | TOOLWINDOW | TRANSPARENT (click-through) | LAYERED
            # HWND_TOPMOST, flags: NOSIZE | NOMOVE | NOACTIVATE | SHOWWINDOW
            f(hw, wintypes.HWND(-1), 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0010 | 0x0040)
        except Exception:
            pass

    POS = Path(os.environ.get("APPDATA", str(Path.home()))) / APP / "widget_pos.json"

    def _clamp(self, pos):
        g = QApplication.primaryScreen().virtualGeometry()
        x = max(g.left(), min(pos.x(), g.right() - self.W))
        y = max(g.top(), min(pos.y(), g.bottom() - self.H))
        return type(pos)(x, y)

    def _default_pos(self, g):
        return QPoint(g.right() - self.W - 16, g.bottom() - self.H - 16)      # bottom-right corner of the screen

    def reveal(self, force=True):
        """Show (or re-raise) the widget. It is never hidden while the account is limited."""
        if not self._placed:
            g = QApplication.primaryScreen().availableGeometry()
            self.move(self._clamp(self._default_pos(g)))                  # always bottom-right (the widget is click-through: nobody can move it, a saved position is ignored)
            self._placed = True
        if not self.isVisible():
            self._intro = 0.0
            self._ia.start()
            self.show()
        else:
            self.move(self._clamp(self.pos()))  # pull it back if it ended up off-screen
        self.raise_()

    def mousePressEvent(self, e):
        self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag is not None and e.buttons() & Qt.LeftButton:
            self.move(self._clamp(e.globalPosition().toPoint() - self._drag))

    def mouseReleaseEvent(self, _):
        if self._drag is not None:
            try:
                self.POS.parent.mkdir(parents=True, exist_ok=True)
                jsave(self.POS, {"x": self.x(), "y": self.y()})
            except Exception:
                pass
        self._drag = None

    def paintEvent(self, _):
        import math as _m
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(QPen(QColor(255, 255, 255, 22), 1))
        p.setBrush(QColor(20, 22, 30, 238))
        p.drawRoundedRect(QRectF(4, 4, self.W - 8, self.H - 8), 18, 18)
        cur = self.current()
        crit = cur is not None and cur <= 60
        waiting = self.waiting
        stale = not waiting and cur is not None and time.time() - self.ts > 30
        if waiting:
            c1, c2, sub = "#6B7186", "#6B7186", "Starting…"
        elif cur is None:
            c1, c2, sub = "#5FD38D", "#3FB6A8", "No time limit"
        elif crit:
            c1, c2, sub = "#FF6B81", "#FF4D6D", "Save your work!"
        elif cur <= self.warn * 60:
            c1, c2, sub = "#FFB347", "#FF8A4C", "Almost time – save your work"
        else:
            c1, c2, sub = "#6C8CFF", "#9B7CFF", "time left"
        if stale:
            sub = "Service not responding"
        ring = QRectF(20, 20, self.H - 40, self.H - 40)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor("#2A2F40"), 7, Qt.SolidLine, Qt.RoundCap))
        p.drawEllipse(ring)
        frac = 0.0 if waiting else (1.0 if cur is None else (cur / self.total if self.total > 0 else 0.0))
        frac = max(0.0, min(1.0, frac)) * self._intro
        if frac > 0.001:
            alpha = int(255 * (0.55 + 0.45 * _m.sin(self._pulse * 2 * _m.pi))) if crit else 255
            a, b = QColor(c1), QColor(c2)
            a.setAlpha(alpha)
            b.setAlpha(alpha)
            g = QLinearGradient(ring.topLeft(), ring.bottomRight())
            g.setColorAt(0, a)
            g.setColorAt(1, b)
            p.setPen(QPen(QBrush(g), 7, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(ring, 90 * 16, int(-frac * 360 * 16))
        p.setPen(QColor("#E6E8EF"))
        p.setFont(QFont("Segoe UI", 26 if cur is None and not waiting else 21, QFont.DemiBold))
        p.drawText(QRectF(112, 22, 170, 44), Qt.AlignLeft | Qt.AlignVCenter,
                   "--:--" if waiting else ("∞" if cur is None else clock(cur)))
        p.setPen(QColor("#FFB347" if stale else (c1 if cur is None or cur <= self.warn * 60 else "#8A90A2")))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(QRectF(112, 66, 175, 22), Qt.AlignLeft | Qt.AlignVCenter, sub)


class IdleWidget(TimeWidget):
    """Small movable always-on-top pill: 'Sign-in screen shutdown' (5 min, on the Windows sign-in screen) or 'Inactive sign-out' (15 min, signed in).
    Reuses TimeWidget's dragging, clamping and always-on-top logic; it just draws something simpler."""
    W, H = 250, 78

    def _default_pos(self, g):  # small movable widget in the top-right corner (until the user drags it elsewhere)
        return QPoint(g.right() - self.W - 16, g.top() + 16)

    def __init__(self, title, total):
        super().__init__()
        self.title, self.total = title, float(total)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(QPen(QColor(255, 255, 255, 22), 1))
        p.setBrush(QColor(20, 22, 30, 238))
        p.drawRoundedRect(QRectF(4, 4, self.W - 8, self.H - 8), 16, 16)
        cur = self.current()
        waiting = self.waiting or cur is None
        crit = not waiting and cur <= 60
        col = "#6B7186" if waiting else ("#FF6B81" if crit else ("#FFB347" if cur <= 180 else "#6C8CFF"))
        p.setPen(QColor("#8A90A2"))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(QRectF(18, 10, self.W - 36, 20), Qt.AlignLeft | Qt.AlignVCenter, self.title)
        p.setPen(QColor("#E6E8EF"))
        p.setFont(QFont("Segoe UI", 20, QFont.DemiBold))
        p.drawText(QRectF(18, 28, 110, 36), Qt.AlignLeft | Qt.AlignVCenter, "--:--" if waiting else clock(cur))
        bar = QRectF(120, 40, self.W - 140, 8)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#2A2F40"))
        p.drawRoundedRect(bar, 4, 4)
        frac = 0.0 if waiting or self.total <= 0 else max(0.0, min(1.0, cur / self.total))
        if frac > 0:
            p.setBrush(QColor(col))
            p.drawRoundedRect(QRectF(bar.x(), bar.y(), bar.width() * frac, bar.height()), 4, 4)


def run_idle():
    """--tg-idle [--login | --user NAME]: the inactivity widget. With --login it runs on the Windows sign-in screen (secure desktop) and
    shows how long until the PC shuts down; otherwise it runs in a user's session and shows how long until the inactive sign-out."""
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    argv = sys.argv
    login = "--login" in argv
    me = "" if login else (argv[argv.index("--user") + 1] if "--user" in argv else os.environ.get("USERNAME", "")).lower()
    sess = 0
    k = None
    if os.name == "nt":
        import ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.restype = ctypes.c_void_p
        k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        s_ = ctypes.c_uint32()
        k.ProcessIdToSessionId(os.getpid(), ctypes.byref(s_))
        sess = s_.value
        mutex = k.CreateMutexW(None, 0, f"Global\\TimeGuardIdle{'Login' if login else 'User'}-{sess}")
        if mutex and ctypes.get_last_error() == 183:
            sys.exit(0)
    w = IdleWidget("Sign-in screen shutdown in" if login else "Inactive sign-out in",
                   IDLE_SHUTDOWN_SECONDS if login else AUTO_LOGOFF_SECONDS)
    w.POS = DATA / ("idle_pos_login.json" if login else f"idle_pos_{me}.json")  # the widget runs as SYSTEM: keep its position in our own folder
    gone = {"since": None}

    def _tick():
        if REMOVED.exists():
            w.hide()
            app.quit()
            return
        d = jload(IDLE_FILE, {})
        fresh = time.time() - d.get("ts", 0) < 30
        left = d.get("login") if login else d.get("sessions", {}).get(str(sess))
        cfg = jload(CFG, {})
        enabled = bool(cfg.get("idle_shutdown", False)) if login else user_auto_logoff(cfg, me)
        shown = fresh and enabled and left is not None
        if shown and not login and IDLE_WIDGET_SHOW_AFTER and AUTO_LOGOFF_SECONDS - left < IDLE_WIDGET_SHOW_AFTER:
            shown = False  # user is active: stay hidden until they have been inactive for a while
        if shown:
            gone["since"] = None
            w.update_status(left, w.total, 0, d.get("ts"))
            w.reveal(force=False)
        else:
            w.hide()
            if login:  # nobody to show it to any more (a user signed in / setting off): end this sign-in-screen copy, the engine restarts it when needed
                gone["since"] = gone["since"] or time.time()
                if time.time() - gone["since"] > 15:
                    app.quit()

    t = QTimer()
    t.timeout.connect(lambda: _guard(_tick))
    t.start(1000)
    _tick()
    sys.exit(app.exec())


def _guard(fn):
    try:
        fn()
    except Exception:
        pass  # the widget must never die because of one bad update


class NoticePopup(QWidget):
    """Small always-on-top message next to the countdown widget (e.g. 'request sent to the administrator').
    It does not steal focus, disappears by itself after a few seconds, and can be dismissed by clicking it."""
    W, H, SECONDS = 340, 104, 10

    def __init__(self, anchor):
        super().__init__(None, Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setFixedSize(self.W, self.H)
        self.anchor, self.title, self.text = anchor, "", ""
        self._hide = QTimer(self)
        self._hide.setSingleShot(True)
        self._hide.timeout.connect(self.hide)

    def show_notice(self, title, text):
        self.title, self.text = title, text
        g = QApplication.primaryScreen().availableGeometry()
        if self.anchor is not None and self.anchor.isVisible():  # sit right above the countdown widget
            a = self.anchor.frameGeometry()
            x, y = a.right() - self.W + 1, a.top() - self.H - 8
            if y < g.top():  # no room above it: put it below instead
                y = a.bottom() + 8
        else:
            x, y = g.right() - self.W - 16, g.bottom() - self.H - 16
        self.move(max(g.left(), min(x, g.right() - self.W)), max(g.top(), min(y, g.bottom() - self.H)))
        self.show()
        self.raise_()
        TimeWidget._pin(self)  # keep it above every other window
        self.update()
        self._hide.start(self.SECONDS * 1000)

    def mousePressEvent(self, _):
        self.hide()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(QPen(QColor(108, 140, 255, 160), 1))
        p.setBrush(QColor(20, 22, 30, 245))
        p.drawRoundedRect(QRectF(4, 4, self.W - 8, self.H - 8), 14, 14)
        p.setPen(QColor("#9B7CFF"))
        p.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
        p.drawText(QRectF(18, 12, self.W - 36, 24), Qt.AlignLeft | Qt.AlignVCenter, "✉  " + self.title)
        p.setPen(QColor("#E6E8EF"))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(QRectF(18, 38, self.W - 36, self.H - 50), Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, self.text)


def make_icon():
    pm = QPixmap(64, 64)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor("#6C8CFF"))
    p.setPen(Qt.NoPen)
    p.drawEllipse(2, 2, 60, 60)
    p.setPen(QPen(QColor("white"), 5, Qt.SolidLine, Qt.RoundCap))
    p.drawLine(32, 32, 32, 14)
    p.drawLine(32, 32, 44, 38)
    p.end()
    return QIcon(pm)


# ───────────── agent: tray icon + warnings in the user's session ─────────────
def run_agent():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    argv = sys.argv
    me = (argv[argv.index("--user") + 1] if "--user" in argv else os.environ.get("USERNAME", "")).lower()
    TimeWidget.POS = DATA / f"widget_pos_{me}.json"  # the agent runs as SYSTEM, so keep the position in our own folder
    mutex = None
    if os.name == "nt":  # one agent per session; the engine also uses this mutex to see that it is alive
        import ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.restype = ctypes.c_void_p
        k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        sess = ctypes.c_uint32()
        k.ProcessIdToSessionId(os.getpid(), ctypes.byref(sess))
        mutex = k.CreateMutexW(None, 0, f"Global\\TimeGuardAgent-{sess.value}")
        if mutex and ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            sys.exit(0)
    tray = QSystemTrayIcon(make_icon())
    w = TimeWidget()
    menu = QMenu()
    act = QAction("Bring remaining time to front", menu)
    act.triggered.connect(lambda: w.reveal())
    menu.addAction(act)
    tray.setContextMenu(menu)
    started, told, shown = time.time(), set(), set()
    tray.activated.connect(lambda *_: w.reveal())
    tray.show()
    flag = {"warn": False, "last": False}

    def _tick():
        if REMOVED.exists():
            tray.hide()
            w.hide()
            app.quit()
            return
        cfg = jload(CFG, {})
        managed = bool(cfg.get("users", {}).get(me, {}).get("enabled"))
        s = jload(STA, {}).get(me)
        if not managed and not s:
            tray.setToolTip(f"{APP}: no limits on this account")
            tray.hide()
            w.hide()
            return
        tray.show()
        for r in list_requests():  # tell the user when the administrator has answered a request
            if (r.get("user") == me and r.get("status") in ("approved", "denied") and r["id"] not in told
                    and r.get("decided_ts", 0) >= started):
                told.add(r["id"])
                ok = r["status"] == "approved"
                text = f"“{r.get('program', '')}” was {'approved' if ok else 'denied'}."
                if r.get("note"):
                    text += f" {r['note']}"
                tray.showMessage(APP, text, QSystemTrayIcon.Information if ok else QSystemTrayIcon.Warning, 15000)
        # (the "request sent to the administrator" notice is handled by check_notice below: it fires on every attempt)
        for r in list_requests():
            if (r.get("user") == me and (r.get("launch") or {}).get("state") == "failed" and r["id"] + "f" not in told
                    and r.get("decided_ts", 0) >= started):
                told.add(r["id"] + "f")
                tray.showMessage(APP, f"“{r.get('program', '')}” was approved but did not start. {r.get('note', '')}",
                                 QSystemTrayIcon.Warning, 15000)
        if not s:  # limited account, but the background service has not reported yet: keep the widget up
            tray.setToolTip(f"{APP}: waiting for the service…")
            w.reveal(force=False)
            return
        r = s["remaining"]
        w.update_status(r, s.get("total", -1), s["warn"], s.get("ts"))
        w.reveal(force=False)
        if r < 0:
            tray.setToolTip(f"{APP}: unlimited")
            return
        cur = w.current()
        tray.setToolTip(f"{APP}: {fmt(cur)} left")
        if cur <= s["warn"] * 60 and not flag["warn"]:
            flag["warn"] = True
            w.reveal()
            tray.showMessage(APP, f"{fmt(cur)} of computer time left. Please save your work.",
                             QSystemTrayIcon.Warning, 10000)
        if cur <= 60 and not flag["last"]:
            flag["last"] = True
            w.reveal()
            tray.showMessage(APP, "Less than one minute left!", QSystemTrayIcon.Critical, 10000)
        if cur > s["warn"] * 60:
            flag["warn"] = flag["last"] = False

    def tick():
        try:
            _tick()
        except Exception:  # the agent must never die because of one bad update
            pass

    blocked_file = DATA / f"blocked_{re.sub(r'[^\w.-]', '_', me)}.json"

    def clear_errors():
        try:
            b = jload(blocked_file, None)
            if isinstance(b, dict) and time.time() - b.get("ts", 0) < 20:
                close_blocked_dialogs(str(b.get("path", "")))
        except Exception:
            pass
    notice_file = DATA / f"notice_{re.sub(r'[^\w.-]', '_', me)}.json"
    popup = NoticePopup(w)
    seen_notice = {"ts": time.time() - 5}  # ignore notices from before this agent started (except the last few seconds)

    def check_notice():
        """The engine wrote a notice: a program of this account asked for admin rights and a request went to the admin."""
        try:
            n = jload(notice_file, None)
            if not isinstance(n, dict) or n.get("ts", 0) <= seen_notice["ts"]:
                return
            seen_notice["ts"] = n["ts"]
            prog = clean_text(n.get("program", ""), 80)
            what = f"“{prog}”" if prog else "This program"
            popup.show_notice("Request sent to the administrator",
                              f"{what} needs administrator approval. Your request to run it has been sent to the "
                              f"administrator. Please wait for the answer.")
            tray.showMessage(APP, f"{what} needs administrator approval. A request to run it was sent to the administrator.",
                             QSystemTrayIcon.Information, 12000)
        except Exception:
            pass

    def watch():
        clear_errors()
        check_notice()
    dtimer = QTimer()
    dtimer.timeout.connect(watch)
    dtimer.start(300)

    t = QTimer()
    t.timeout.connect(tick)
    t.start(2000)
    tick()
    sys.exit(app.exec())


# ───────────────────────── admin GUI ─────────────────────────
class NoWheelSpin(QSpinBox):
    """Spin box that ignores the mouse wheel, so scrolling the page never changes a value by accident (the wheel scrolls the page instead)."""

    def wheelEvent(self, e):
        e.ignore()  # not handled here -> Qt passes it on to the scroll area


class NoWheelTime(QTimeEdit):
    def wheelEvent(self, e):
        e.ignore()


class NoWheelCombo(QComboBox):
    def wheelEvent(self, e):
        e.ignore()


class DurationBox(NoWheelSpin):
    """Minutes spin box that reads like '2 h 15 m'; 0 and the top value have friendly names."""

    def __init__(self, zero, top=1440, top_text="Unlimited", step=15):
        super().__init__()
        self.zero, self.top, self.top_text = zero, top, top_text
        self.setRange(0, top)
        self.setSingleStep(step)

    def textFromValue(self, v):
        if v == 0:
            return self.zero
        if self.top_text and v == self.top:
            return self.top_text
        h, m = divmod(v, 60)
        return f"{h} h {m:02d} m" if h else f"{m} m"

    def valueFromText(self, text):
        t = text.strip().lower()
        if t == self.zero.lower():
            return 0
        if self.top_text and t == self.top_text.lower():
            return self.top
        n = [int(x) for x in re.findall(r"\d+", t)]
        if not n:
            return 0
        if "h" in t:
            return n[0] * 60 + (n[1] if len(n) > 1 else 0)
        return n[0]

    def validate(self, text, pos):
        return (QValidator.State.Acceptable, text, pos)


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


_RUNKEY = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"


def _procs_ps(action):
    """PowerShell snippet that finds the running TimeGuard engine/agent processes (never this GUI)."""
    # --tg-engine / --tg-agent are ours; the old names count only when the program is timeguard.py/.exe (WoL Host also has an --agent)
    return ("Get-CimInstance Win32_Process | Where-Object { ($_.CommandLine -match '--tg-(engine|agent|pad|idle)' -or "
            "$_.CommandLine -match 'timeguard\\.(py|exe)\\W+--(engine|agent)') -and "
            f"$_.ProcessId -ne {os.getpid()} }} | " + action)


def _stop_everything():
    """Stops the engine and every widget (also those of older versions) and removes old startup entries."""
    for t in (AGENT_TASK, TASK):
        run("schtasks", "/End", "/TN", t)  # fails harmlessly if it is not running
    run("schtasks", "/Delete", "/TN", AGENT_TASK, "/F")  # old versions used a per-user task for the widget
    for view in ("/reg:64", "/reg:32"):  # ... and a startup entry (maybe in either registry view)
        run("reg", "delete", _RUNKEY, "/v", "TimeGuardAgent", "/f", view)
    run("powershell", "-NoProfile", "-Command",
        _procs_ps("ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"))
    time.sleep(1.5)


def _still_running():
    r = run("powershell", "-NoProfile", "-Command", "@(" + _procs_ps("Select-Object -ExpandProperty ProcessId") + ").Count")
    return int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0


def install_protection():
    DATA.mkdir(parents=True, exist_ok=True)
    _stop_everything()  # also frees the old files so they can be replaced
    REMOVED.unlink(missing_ok=True)
    dest = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / APP
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if getattr(sys, "frozen", False):
            if _onedir():                                     # injected by wol_host.py: the whole program folder is installed, nothing is unpacked at start
                base = [copy_app_dir(dest)]
            else:
                shutil.copy2(sys.executable, dest / "TimeGuard.exe")
                base = [str(dest / "TimeGuard.exe")]
        else:
            shutil.copy2(__file__, dest / Path(__file__).name)
            py = Path(sys.executable)
            pw = py.with_name("pythonw.exe")
            base = [str(pw if pw.exists() else py), str(dest / Path(__file__).name)]
    except shutil.SameFileError:  # already running from the installed copy
        base = [sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)])
    cmd = " ".join(f'"{x}"' for x in base)
    for p in (DATA, dest):  # standard users: read-only; SYSTEM + Administrators: full
        run("icacls", str(p), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    # Files that already exist keep their old access lists (the folder rule above only reaches new files), which can stop
    # the SYSTEM engine from replacing them ("Access is denied: usage.json.tmp -> usage.json"). Clear leftovers and reset them.
    for f in list(DATA.glob("*.tmp")):
        try:
            f.unlink()
        except OSError:
            pass
    for f in list(DATA.glob("*.json")) + list(DATA.glob("*.flag")) + list(DATA.glob("*.log")):
        run("takeown", "/F", str(f), "/A")
        run("icacls", str(f), "/reset")
    # One SYSTEM task does everything: it counts time, enforces limits and keeps the countdown widget running
    # in every limited user's session (as SYSTEM, so the user cannot close it).
    r = run("schtasks", "/Create", "/TN", TASK, "/TR", cmd + " --tg-engine", "/SC", "ONSTART",
            "/RU", "SYSTEM", "/RL", "HIGHEST", "/F")
    if r.returncode != 0:
        raise RuntimeError("Could not create the background task:\n" + (r.stderr or r.stdout).strip())
    problems = []
    if not getattr(sys, "frozen", False):
        try:  # the service runs as SYSTEM and cannot see packages installed with "pip install --user"
            import PySide6, site
            if str(Path(PySide6.__file__)).lower().startswith(site.getusersitepackages().lower()):
                problems.append("PySide6 is installed only for your own Windows user. The countdown widget (which runs "
                                "as SYSTEM) will not start. Install it for all users or build an .exe.")
        except Exception:
            pass
    t0 = time.time()
    r = run("schtasks", "/Run", "/TN", TASK)
    if r.returncode != 0:
        problems.append("The task was created but could not be started: " + (r.stderr or r.stdout).strip())
    else:
        for _ in range(90):  # wait up to 45 s for the engine's first heartbeat (its first round asks PowerShell, which is slow)
            try:
                if STA.stat().st_mtime > t0:
                    break
            except OSError:
                pass
            time.sleep(0.5)
        else:
            try:
                tail = "\n".join((DATA / "engine.log").read_text("utf-8").splitlines()[-3:])
            except OSError:
                tail = ""
            problems.append("The service was started but is not reporting. See C:\\ProgramData\\TimeGuard\\engine.log"
                            + (":\n" + tail if tail else "."))
    return "\n".join(problems) or None


AUTOSTART_TASK = "TimeGuardAdmin"


def gui_command():
    """Command line that opens the admin window (uses the installed copy when there is one)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--tg-gui"]
    inst = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / APP / Path(__file__).name
    script = str(inst if inst.is_file() else Path(os.path.abspath(__file__)))
    py = Path(sys.executable)
    pw = py.with_name("pythonw.exe")  # no console window
    return [str(pw if pw.exists() else py), script, "--tg-gui"]      # the script is wol_host.py: --tg-gui makes it open TimeGuard


def autostart_exists():
    """True/False whether the sign-in task exists; None if Windows could not be asked."""
    try:
        return run("schtasks", "/Query", "/TN", AUTOSTART_TASK).returncode == 0
    except Exception:
        return None


def set_autostart(on):
    """Create or delete the task that opens TimeGuard (minimized to the tray) when this user signs in.
    A task with 'highest privileges' starts elevated without a UAC prompt. Returns a problem text or None."""
    if not on:
        r = run("schtasks", "/Delete", "/TN", AUTOSTART_TASK, "/F")
        if r.returncode != 0 and autostart_exists():
            return (r.stderr or r.stdout).strip()
        return None
    user = os.environ.get("USERNAME", "")
    dom = os.environ.get("USERDOMAIN", "")
    who = f"{dom}\\{user}" if dom and user else user
    cmd = " ".join(f'"{x}"' for x in gui_command()) + " --tray"
    r = run("schtasks", "/Create", "/TN", AUTOSTART_TASK, "/TR", cmd, "/SC", "ONLOGON",
            "/RU", who, "/IT", "/RL", "HIGHEST", "/F")
    if r.returncode != 0:
        return (r.stderr or r.stdout).strip() or "schtasks failed"
    return None


def uninstall_protection():
    """Stops and removes the background service and the widgets. Returns a text with problems, if any."""
    problems = []
    try:  # tells any running engine/agent of this version to quit by themselves
        DATA.mkdir(parents=True, exist_ok=True)
        REMOVED.write_text("removed")
    except OSError:
        pass
    for nm, u in jload(CFG, {}).get("users", {}).items():  # never leave an account disabled behind
        if u.get("auto_account"):
            run("net", "user", nm, "/active:yes")
    _stop_everything()
    r = run("schtasks", "/Delete", "/TN", TASK, "/F")
    if r.returncode != 0 and run("schtasks", "/Query", "/TN", TASK).returncode == 0:
        problems.append("The background task could not be deleted: " + (r.stderr or r.stdout).strip())
    n = _still_running()
    if n:
        problems.append(f"{n} TimeGuard process(es) are still running. Sign out and in again, or restart the PC.")
    shutil.rmtree(LIVE, ignore_errors=True)  # screen frames of older versions
    try:
        STA.unlink()
    except OSError:
        pass
    if not problems:
        shutil.rmtree(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / APP, ignore_errors=True)
    return "\n".join(problems) or None


class Card(QFrame):
    def __init__(self, name, on_apply):
        super().__init__()
        self.setObjectName("card")
        self.name, self._apply = name, on_apply
        self.bal, self.pending, self._shown = None, 0, False
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(10)
        top = QHBoxLayout()
        title = QLabel(name.title())
        title.setObjectName("h2")
        self.state = QLabel()
        self.state.setObjectName("muted")
        self.left = QLabel()
        self.left.setObjectName("big")
        top.addWidget(title)
        top.addSpacing(12)
        top.addWidget(self.state)
        top.addStretch()
        top.addWidget(self.left)
        v.addLayout(top)
        self.bar = AnimBar()
        v.addWidget(self.bar)
        self.info = QLabel()
        self.info.setObjectName("muted")
        v.addWidget(self.info)
        self.limit = QLabel()
        v.addWidget(self.limit)
        for sign, label in ((1, "Add time"), (-1, "Remove time")):
            row = QHBoxLayout()
            l = QLabel(label)
            l.setObjectName("muted")
            l.setFixedWidth(90)
            row.addWidget(l)
            for m in (15, 30, 60):
                b = QPushButton(f"{'+' if sign > 0 else '−'}{m} min")
                b.clicked.connect(lambda _=False, d=m * sign: self.stage(d))
                row.addWidget(b)
            extra = QPushButton("Custom…")
            extra.clicked.connect(lambda _=False, sg=sign: self._custom(sg))
            row.addWidget(extra)
            row.addStretch()
            v.addLayout(row)
        ar = QHBoxLayout()
        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setObjectName("primary")
        self.btn_apply.clicked.connect(self._do_apply)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self._do_cancel)
        self.hint = QLabel("Not applied yet")
        self.hint.setObjectName("muted")
        for w in (self.btn_apply, self.btn_cancel, self.hint):
            ar.addWidget(w)
            w.setVisible(False)
        ar.addStretch()
        v.addLayout(ar)

    def stage(self, delta):
        self.pending += delta
        self._show_pending()

    def _custom(self, sign):
        text = "Minutes to add:" if sign > 0 else "Minutes to remove:"
        m, ok = QInputDialog.getInt(self, APP, text, 15, 1, 59940, 5)
        if ok and m:
            self.stage(sign * m)

    def _do_apply(self):
        if self.pending:
            delta, self.pending = self.pending, 0
            self._show_pending()
            self._apply(self.name, delta)

    def _do_cancel(self):
        self.pending = 0
        self._show_pending()

    def _show_pending(self):
        lab = lambda sec: "0 m" if sec <= 0 else fmt(sec)
        bal = self.bal or 0
        if not self.pending:
            self.limit.setText(f"Time balance:  {lab(bal)}")
            self.limit.setStyleSheet("")
        else:
            sign = "+" if self.pending > 0 else "−"
            self.limit.setText(f"Time balance:  {lab(bal)}   →   {lab(bal + self.pending * 60)}"
                               f"   ({sign}{abs(self.pending)} m)")
            self.limit.setStyleSheet("color:#9B7CFF;font-weight:600")
        show = bool(self.pending)
        for w in (self.btn_apply, self.btn_cancel, self.hint):
            w.setVisible(show)
            if show and not self._shown:
                fade_in(w, dur=240)
        self._shown = show

    def refresh(self, u, ud, online):
        rem, why = remaining_info(u, ud)
        used = ud.get(dt.date.today().isoformat(), 0)
        credit = u.get("credit_min")
        self.bal = None if credit is None else max(credit * 60 - total_used(ud), 0)
        self._show_pending()
        self.state.setText("● Signed in" if online else "○ Not signed in")
        total = used + max(rem, 0) if rem is not None else 0
        self.bar.set_value(used / total if total > 0 else (1.0 if rem is not None else 0.0))
        self.left.setText("∞" if rem is None else fmt(rem))
        self.left.setStyleSheet("color:#5FD38D" if rem is None else ("color:#FF6B81" if rem <= 300 else ""))
        note = ""
        if why and why != "balance":  # the big number is the smallest of all limits - say which one it is
            note = {"weekly": "the weekly cap", "monthly": "the monthly cap"}.get(why) or (
                f"the allowed hours (end at {why[6:]})" if why.startswith("hours:")
                else f"the allowed hours (open at {why[7:]})")
        self.info.setText(f"Used today: {fmt(used)}" + (f"   ·   Time left is limited by {note}" if note else ""))


def slide(w, show, animate=True):
    """Expand or collapse a widget with a smooth height animation."""
    old = getattr(w, "_slide", None)
    if old is not None:
        old.stop()
    if not animate:
        w.setMaximumHeight(16777215)
        w.setVisible(show)
        return
    if show:
        w.setMaximumHeight(0)
        w.setVisible(True)
        start, end = 0, w.sizeHint().height()
    else:
        start, end = w.height(), 0
    a = QPropertyAnimation(w, b"maximumHeight", w)
    a.setDuration(280)
    a.setEasingCurve(QEasingCurve.OutCubic)
    a.setStartValue(start)
    a.setEndValue(end)

    def done():
        w.setMaximumHeight(16777215)
        if not show:
            w.setVisible(False)
    a.finished.connect(done)
    w._slide = a
    a.start()


def list_drives():
    """[(letter, label)] of every drive present on this PC (fixed, removable, network, optical), e.g. ("D", "Games - local disk")."""
    out = []
    if os.name != "nt":
        return out
    try:
        import ctypes
        k = ctypes.windll.kernel32
        mask, sysd = k.GetLogicalDrives(), os.environ.get("SystemDrive", "C:")[:1].upper()
        kinds = {2: "removable", 3: "local disk", 4: "network", 5: "disc drive", 6: "RAM disk"}
        for i in range(26):
            L = chr(65 + i)
            if not mask & (1 << i):
                continue
            typ = k.GetDriveTypeW(f"{L}:\\")
            buf = ctypes.create_unicode_buffer(64)
            ok = k.GetVolumeInformationW(f"{L}:\\", buf, 64, None, None, None, None, 0)
            name = buf.value if ok and buf.value else ""
            what = kinds.get(typ, "drive") + (", Windows" if L == sysd else "")
            out.append((L, f"{name} ({what})" if name else f"({what})"))
    except Exception:
        pass
    return out


class AccountCard(QFrame):
    """One Windows account on the Accounts page - same card look as the dashboard, settings save automatically."""

    def __init__(self, name, on_save):
        super().__init__()
        self.setObjectName("card")
        self.name, self._save, self._loading = name, on_save, False
        self._entry, self._dirty = None, False
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(12)
        top = QHBoxLayout()
        title = QLabel(name.title())
        title.setObjectName("h2")
        self.state = QLabel()
        self.state.setObjectName("muted")
        self.on = Toggle("Manage")
        top.addWidget(title)
        top.addSpacing(12)
        top.addWidget(self.state)
        top.addStretch()
        top.addWidget(self.on)
        v.addLayout(top)

        self.body = QWidget()
        self.body.setObjectName("body")
        g = QGridLayout(self.body)
        g.setContentsMargins(0, 4, 0, 0)
        g.setHorizontalSpacing(16)
        g.setVerticalSpacing(12)
        self.week = DurationBox("No limit", 7 * 1440, "", 60)
        self.month = DurationBox("No limit", 31 * 1440, "", 60)
        self.sched = Toggle("Only allow use between")
        self.auto = Toggle("Disable the Windows account outside these hours, enable it when they begin")
        self.tfrom, self.tto = NoWheelTime(), NoWheelTime()
        for te in (self.tfrom, self.tto):
            te.setDisplayFormat("HH:mm")
        self.warn = NoWheelSpin()
        self.warn.setRange(1, 30)
        self.warn.setSuffix(" min before")
        self.act = NoWheelCombo()
        self.act.addItems(["Log off the user", "Lock the screen"])
        g.addWidget(QLabel("Weekly cap"), 0, 0)
        g.addWidget(self.week, 0, 1)
        g.addWidget(QLabel("Monthly cap"), 0, 2)
        g.addWidget(self.month, 0, 3)
        g.addWidget(self.sched, 1, 0, 1, 2)
        g.addWidget(self.tfrom, 1, 2)
        g.addWidget(self.tto, 1, 3)
        g.addWidget(self.auto, 2, 0, 1, 4)
        g.addWidget(QLabel("Warn"), 3, 0)
        g.addWidget(self.warn, 3, 1)
        g.addWidget(QLabel("When time is up"), 3, 2)
        g.addWidget(self.act, 3, 3)
        self.logoff = Toggle("Sign out after 15 minutes of inactivity")
        g.addWidget(self.logoff, 4, 0, 1, 4)
        g.addWidget(self._small_note("No keyboard, mouse or game-controller input for 15 minutes signs this user out (a warning appears a minute "
                                     "before, and a small countdown widget shows the time left). Unsaved work is lost."), 5, 0, 1, 4)
        self.drv = Toggle("Restrict access to specific drives")
        g.addWidget(self.drv, 8, 0, 1, 4)
        self.drv_box = QPushButton("Choose drives…")  # a drop-down list of every drive on this PC, each with a tick box
        self.drv_menu = QMenu(self.drv_box)
        self.drv_box.setMenu(self.drv_menu)
        self.drv_cb = {}
        for letter, label in list_drives():
            self._add_drive(letter, label)
        self._drv_text()
        g.addWidget(self.drv_box, 9, 0, 1, 2)
        self.drv_note = self._small_note("Tick the drives this user must NOT be able to open. They are hidden in File Explorer and cannot be opened from it or from "
                                         "Open / Save dialogs. Takes effect the next time this user signs in. This is a Windows policy, not a lock: someone who "
                                         "types a path in a command prompt can still reach a drive, so use NTFS permissions as well for strong protection. "
                                         "The Windows drive is only HIDDEN (not blocked), so the Desktop, Documents and programs keep working. Administrator accounts are not restricted.")
        g.addWidget(self.drv_note, 10, 0, 1, 4)
        self.drv.toggled.connect(self._drv_vis)
        self._drv_vis(False)
        v.addWidget(self.body)
        ar = QHBoxLayout()
        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setObjectName("primary")
        self.btn_apply.clicked.connect(self._do_apply)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self._do_cancel)
        self.hint = QLabel("Not applied yet")
        self.hint.setObjectName("muted")
        for wdg in (self.btn_apply, self.btn_cancel, self.hint):
            ar.addWidget(wdg)
            wdg.setVisible(False)
        ar.addStretch()
        v.addLayout(ar)
        self.on.toggled.connect(self._toggled)
        self.sched.toggled.connect(self.auto.setEnabled)  # only available together with the allowed hours
        for sig in (self.drv.toggled, self.logoff.toggled, self.sched.toggled, self.auto.toggled, self.week.valueChanged, self.month.valueChanged, self.warn.valueChanged,
                    self.tfrom.timeChanged, self.tto.timeChanged, self.act.currentIndexChanged):
            sig.connect(self._changed)

    def _add_drive(self, letter, label=""):
        if letter in self.drv_cb:
            return
        cb = QCheckBox(f"  {letter}:   {label}".rstrip())
        cb.setStyleSheet("QCheckBox{padding:7px 14px;background:transparent}")
        cb.toggled.connect(lambda on, L=letter: self._drive_ticked(L, on))
        act = QWidgetAction(self.drv_menu)  # a check box inside the menu keeps it open while several drives are ticked
        act.setDefaultWidget(cb)
        self.drv_menu.addAction(act)
        self.drv_cb[letter] = cb

    def _drive_ticked(self, letter, on):
        self._drv_text()
        self._changed()

    def _drv_text(self):
        on = sorted(k for k, c in self.drv_cb.items() if c.isChecked())
        self.drv_box.setText("Blocked: " + ", ".join(f"{k}:" for k in on) if on else "Choose drives to block…")

    def _drv_vis(self, on):
        self.drv_box.setVisible(bool(on))
        self.drv_note.setVisible(bool(on))

    @staticmethod
    def _small_note(text):
        n = QLabel(text)
        n.setObjectName("muted")
        n.setWordWrap(True)
        return n

    def values(self):
        return {"enabled": self.on.isChecked(), "weekly": self.week.value(), "monthly": self.month.value(),
                "use_schedule": self.sched.isChecked(), "auto_account": self.auto.isChecked(),
                "from": self.tfrom.time().toString("HH:mm"), "to": self.tto.time().toString("HH:mm"),
                "warn": self.warn.value(), "action": "lock" if self.act.currentIndex() else "logoff",
                "auto_logoff": self.logoff.isChecked(),
                "restrict_drives": self.drv.isChecked(), "block_drives": sorted(k for k, c in self.drv_cb.items() if c.isChecked())}

    def load(self, entry):
        u = {**default_user(), **(entry or {})}
        self._entry = dict(entry) if entry else None
        self._loading = True
        self.on.setChecked(bool(entry and entry.get("enabled")))
        self.logoff.setChecked(bool((entry or {}).get("auto_logoff", jload(CFG, {}).get("auto_logoff", False))))
        self.week.setValue(u["weekly"])
        self.month.setValue(u["monthly"])
        self.sched.setChecked(u["use_schedule"])
        self.auto.setChecked(u.get("auto_account", False))
        self.auto.setEnabled(self.sched.isChecked())
        self.tfrom.setTime(QTime.fromString(u["from"], "HH:mm"))
        self.tto.setTime(QTime.fromString(u["to"], "HH:mm"))
        self.warn.setValue(u["warn"])
        self.act.setCurrentIndex(1 if u["action"] == "lock" else 0)
        for k in u.get("block_drives", []):  # a saved drive that is not plugged in right now stays in the list
            self._add_drive(str(k).upper())
        for k, c in self.drv_cb.items():
            c.setChecked(k in [str(x).upper() for x in u.get("block_drives", [])])
        self._drv_text()
        self.drv.setChecked(bool(u.get("restrict_drives")))
        self._drv_vis(self.drv.isChecked())
        self._loading = False
        self._state(animate=False)
        self._set_dirty(False)

    def _state(self, animate=True):
        on = self.on.isChecked()
        self.state.setText("● Managed" if on else "○ Not managed")
        self.state.setStyleSheet("color:#5FD38D" if on else "")
        slide(self.body, on, animate)

    def _toggled(self, _):
        if not self._loading:
            self._state()
            self._set_dirty(True)

    def _changed(self, *_):
        if not self._loading:
            self._set_dirty(True)

    def _set_dirty(self, on):
        show_new = on and not self._dirty
        self._dirty = on
        for wdg in (self.btn_apply, self.btn_cancel, self.hint):
            wdg.setVisible(on)
            if show_new:
                fade_in(wdg, dur=240)

    def flush(self):  # nothing is saved without pressing Apply
        pass

    def _do_apply(self):
        v = self.values()
        self._save(self.name, v)
        self._entry = v
        self._set_dirty(False)

    def _do_cancel(self):
        self.load(self._entry)


class Job(QThread):
    """Runs a slow function (PowerShell, schtasks...) in the background so the window never freezes."""
    done = Signal(object, object, object)  # job, result, error

    def __init__(self, fn):
        super().__init__()
        self.fn, self.cb = fn, None

    def run(self):
        try:
            self.done.emit(self, self.fn(), None)
        except Exception as e:
            e.tb_text = traceback.format_exc()  # shown in the error box so a failure can be located
            self.done.emit(self, None, e)


class BusyBar(QWidget):
    """Thin indeterminate progress bar (a gradient segment sliding back and forth)."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(6)
        self._p = 0.0
        self._a = QVariantAnimation(self)
        self._a.setDuration(1100)
        self._a.setStartValue(0.0)
        self._a.setEndValue(1.0)
        self._a.setLoopCount(-1)
        self._a.valueChanged.connect(self._set)
        self.setVisible(False)

    def _set(self, v):
        self._p = v
        self.update()

    def start(self):
        self.setVisible(True)
        self._a.start()

    def stop(self):
        self._a.stop()
        self.setVisible(False)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect())
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#232733"))
        p.drawRoundedRect(r, 3, 3)
        seg = r.width() * 0.35
        x = (r.width() + seg) * self._p - seg
        x0, x1 = max(0.0, x), min(r.width(), x + seg)
        if x1 > x0:
            g = QLinearGradient(x0, 0, x1, 0)
            g.setColorAt(0, QColor("#6C8CFF"))
            g.setColorAt(1, QColor("#9B7CFF"))
            p.setBrush(QBrush(g))
            p.drawRoundedRect(QRectF(x0, 0, x1 - x0, r.height()), 3, 3)


class RequestRow(QFrame):
    """One install request in the administrator's list."""

    def __init__(self, r, on_approve, on_deny):
        super().__init__()
        self.setObjectName("card")
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 14, 20, 14)
        v.setSpacing(4)
        when = dt.datetime.fromtimestamp(r.get("ts", 0)).strftime("%d %b %H:%M")

        def label(text, name=""):
            l = QLabel(text)
            l.setTextFormat(Qt.PlainText)  # request text comes from a user: never interpret it as HTML
            l.setWordWrap(True)
            if name:
                l.setObjectName(name)
            return l
        v.addWidget(label(r.get("program", "?"), "h2"))
        v.addWidget(label(f"{r.get('user', '?')}  ·  {when}", "muted"))
        if r.get("auto"):
            v.addWidget(label("Sent automatically: a program asked Windows for administrator rights."
                              + ("" if r.get("path") else " The program could not be identified (Approve lets you pick its installer)."), "muted"))
        if r.get("path"):
            v.addWidget(label("File: " + r["path"], "muted"))
        if r.get("hint"):
            v.addWidget(label(r["hint"], "muted"))
        if r.get("link"):
            v.addWidget(label("Source: " + r["link"], "muted"))
        if r.get("reason"):
            v.addWidget(label("Reason: " + r["reason"]))
        st = r.get("status")
        if st == "pending":
            row = QHBoxLayout()
            ok = QPushButton("Approve")
            ok.setObjectName("primary")
            ok.clicked.connect(lambda: on_approve(r))
            no = QPushButton("Deny")
            no.setObjectName("danger")
            no.clicked.connect(lambda: on_deny(r))
            row.addWidget(ok)
            row.addWidget(no)
            row.addStretch()
            v.addLayout(row)
        else:
            done = dt.datetime.fromtimestamp(r.get("decided_ts", 0)).strftime("%d %b %H:%M")
            ls = (r.get("launch") or {}).get("state")
            tail = {"queued": "  ·  starting…", "started": "  ·  started on their account"}.get(ls, "")
            if r.get("note") and st == "denied" or ls == "failed":
                tail += "  ·  " + r.get("note", "")
            c = "#5FD38D" if st == "approved" and ls != "failed" else "#FF8A9A"
            l = label(f"{st.capitalize()} {done}{tail}")
            l.setStyleSheet(f"color:{c}")
            v.addWidget(l)


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP)
        self.setWindowIcon(make_icon())
        self.resize(1040, 700)
        self.cfg = jload(CFG, {})
        self.cfg.setdefault("users", {})
        usage0, migrated = jload(USE, {}), False
        for nm, u in self.cfg["users"].items():  # older versions used daily limits: start with a fresh 24 h balance
            if "credit_min" not in u:
                u["credit_min"] = math.ceil(total_used(usage0.get(nm, {})) / 60) + 1440
                migrated = True
            for k in ("daily", "daily_min", "bonus_date", "bonus_min"):
                u.pop(k, None)
        if migrated:
            self.save_cfg()
        self.cards = {}
        self.admins = set()
        self.acc_cards = {}
        self._jobs, self._acc, self._acc_busy, self._busy = [], [], False, False
        root = QWidget()
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(220)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(14, 22, 14, 14)
        lbl = QLabel("⏱  Time<span style='color:#6C8CFF'>Guard</span>")
        lbl.setObjectName("title")
        sv.addWidget(lbl)
        sv.addSpacing(18)
        self.stack = QStackedWidget()
        self.navs = []
        pages = [("Dashboard", self.page_dash()), ("Accounts", self.page_accounts()),
                 ("Requests", self.page_requests()),
                 ("Settings", self.page_settings())]
        for i, (name, page) in enumerate(pages):
            b = QPushButton(name)
            b.setObjectName("nav")
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, i=i: self.go(i))
            sv.addWidget(b)
            self.navs.append(b)
            self.stack.addWidget(page)
        self.req_nav = self.navs[2]
        sv.addStretch()
        self.ind = QFrame(side)  # sliding accent bar next to the active menu item
        self.ind.setStyleSheet("background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #6C8CFF,stop:1 #9B7CFF);border-radius:2px")
        self.ind.setGeometry(0, 0, 4, 0)
        h.addWidget(side)
        if self.EMBED:
            side.hide()  # inside WoL Host these pages are chosen from the TimeGuard sub-menu of the host's own sidebar
        h.addWidget(self.stack, 1)
        self.pending = 0
        self.go(0)
        timer = QTimer(self)
        timer.timeout.connect(self.tick)
        timer.start(3000)
        self.tick()
        self._setup_tray()

    # ── system tray: closing the window only hides it ──
    _quit, _authed, tray, _tray_told = False, True, None, False

    EMBED = False  # True inside WoL Host: the window is a docked tab, so there is no tray icon to hide it in

    def _setup_tray(self):
        if self.EMBED or not QSystemTrayIcon.isSystemTrayAvailable():
            return  # no tray on this system: the close button really closes the program
        self.tray = QSystemTrayIcon(make_icon(), self)
        self.tray.setToolTip(f"{APP} (administrator)")
        menu = QMenu()
        a_open = QAction("Open TimeGuard", menu)
        a_open.triggered.connect(self.reveal)
        a_quit = QAction("Quit", menu)
        a_quit.triggered.connect(self.quit_app)
        menu.addAction(a_open)
        menu.addSeparator()
        menu.addAction(a_quit)
        self._tray_menu = menu  # keep a reference
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.reveal() if reason in (
            QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.show()

    def to_tray(self):
        """Hide the window but keep the program (and the tray icon) running."""
        self.flush_save()
        self._authed = False  # the admin password (if any) is asked again when the window comes back
        self.hide()
        if not self._tray_told and self.tray is not None:
            self._tray_told = True
            self.tray.showMessage(APP, "TimeGuard is still running in the tray. Click the icon to open it again; "
                                       "right-click it to quit.", QSystemTrayIcon.Information, 6000)

    def reveal(self):
        """Bring the window back from the tray (asks for the admin password first if one is set)."""
        if not self._authed:
            if not authenticate(jload(CFG, {})):
                return
            self._authed = True
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()

    def quit_app(self):
        """Really quit (the background protection keeps running; only this window ends)."""
        if not self._authed and not authenticate(jload(CFG, {})):
            return
        self._quit = True
        self.close()
        if self.tray is not None:
            self.tray.hide()
        QApplication.quit()

    def showEvent(self, e):
        super().showEvent(e)
        QTimer.singleShot(0, lambda: self._move_ind(self.stack.currentIndex(), False))

    def closeEvent(self, e):
        if not self._quit and self.tray is not None:
            e.ignore()  # the X button minimizes to the tray
            self.to_tray()
            return
        self.flush_save()
        for j in list(self._jobs):  # let background work finish cleanly
            j.wait(10000)
        super().closeEvent(e)

    def run_async(self, fn, cb):
        """Run fn() in a background thread, then call cb(result, error) in the window thread."""
        job = Job(fn)
        job.cb = cb
        self._jobs = [j for j in self._jobs if j.isRunning()] + [job]
        job.done.connect(self._job_done)
        job.start()

    def _job_done(self, job, result, error):
        if job.cb:
            job.cb(result, error)

    def _move_ind(self, i, animate=True):
        g = self.navs[i].geometry()
        tgt = QRect(0, g.y() + 9, 4, max(g.height() - 18, 0))
        self.ind.raise_()
        if not animate or self.ind.height() == 0:
            self.ind.setGeometry(tgt)
            return
        a = QPropertyAnimation(self.ind, b"geometry", self)
        a.setDuration(320)
        a.setEndValue(tgt)
        a.setEasingCurve(QEasingCurve.OutCubic)
        a.start(QAbstractAnimation.DeleteWhenStopped)

    def go(self, i):
        self.flush_save()
        if i == 1:
            self.refresh_accounts()
        changed = self.stack.currentIndex() != i
        self.stack.setCurrentIndex(i)
        if changed:
            fade_in(self.stack.currentWidget(), dur=280)
        for k, b in enumerate(self.navs):
            b.setChecked(k == i)
        if self.isVisible():
            self._move_ind(i)

    def save_cfg(self):
        DATA.mkdir(parents=True, exist_ok=True)
        jsave(CFG, self.cfg)

    # ── dashboard ──
    def page_dash(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(32, 28, 32, 28)
        h1 = QLabel("Dashboard")
        h1.setObjectName("h1")
        v.addWidget(h1)
        sub = QLabel("Live usage for every limited account.")
        sub.setObjectName("muted")
        v.addWidget(sub)
        v.addSpacing(10)
        tiles = QHBoxLayout()
        tiles.setSpacing(14)
        self.t_acc = StatTile("Managed accounts", lambda x: str(int(round(x))))
        self.t_used = StatTile("Used today (all accounts)", fmt)
        self.t_prot = StatTile("Protection")
        for t in (self.t_acc, self.t_used, self.t_prot):
            tiles.addWidget(t)
        v.addLayout(tiles)
        v.addSpacing(10)
        self.empty = QLabel("No accounts are limited yet. Open “Accounts” to add one.")
        self.empty.setObjectName("muted")
        v.addWidget(self.empty)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        inner = QWidget()
        self.card_box = QVBoxLayout(inner)
        self.card_box.setSpacing(14)
        self.card_box.addStretch()
        sc.setWidget(inner)
        v.addWidget(sc, 1)
        return w

    def apply_delta(self, name, minutes):
        """Dashboard card pressed Apply: add (or remove) minutes of total time."""
        u = self.cfg["users"][name]
        used_min = total_used(jload(USE, {}).get(name, {})) / 60
        new = u.get("credit_min", used_min) + minutes
        u["credit_min"] = min(max(new, used_min), used_min + 59940)  # balance stays between 0 and 999 h
        self.save_cfg()
        self.tick()

    def tick(self):
        usage, status = jload(USE, {}), jload(STA, {})
        names = [n for n, u in self.cfg["users"].items() if u.get("enabled") and n not in self.admins]
        if names != list(self.cards):
            for c in self.cards.values():
                c.setParent(None)
            self.cards = {}
            for n in names:
                self.cards[n] = Card(n, self.apply_delta)
                self.card_box.insertWidget(self.card_box.count() - 1, self.cards[n])
                fade_in(self.cards[n], delay=90 * len(self.cards))
        self.empty.setVisible(not names)
        for n, c in self.cards.items():
            c.refresh(self.cfg["users"][n], usage.get(n, {}), n in status)
        alive = service_alive()
        self.prot.setText("● Protection is running" if alive else "○ Protection is not running")
        self.prot.setStyleSheet("color:#5FD38D" if alive else "color:#FF8A9A")
        self.t_prot.set_text("Running" if alive else "Stopped", "#5FD38D" if alive else "#FF8A9A")
        installed = alive or (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / APP).exists()
        today = dt.date.today().isoformat()
        self.t_acc.animate_to(len(names))
        self.t_used.animate_to(sum(usage.get(n, {}).get(today, 0) for n in names))
        self.refresh_requests()

    # ── accounts ──
    def page_accounts(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(32, 28, 32, 28)
        head = QHBoxLayout()
        h1 = QLabel("Accounts")
        h1.setObjectName("h1")
        self.saved = QLabel("")
        self.saved.setObjectName("muted")
        self._saved_fx = QGraphicsOpacityEffect(self.saved)
        self._saved_fx.setOpacity(0.0)
        self.saved.setGraphicsEffect(self._saved_fx)
        self._saved_anim = QPropertyAnimation(self._saved_fx, b"opacity", self)
        self._saved_anim.setDuration(2400)
        for pos, val in ((0.0, 0.0), (0.08, 1.0), (0.8, 1.0), (1.0, 0.0)):
            self._saved_anim.setKeyValueAt(pos, val)
        head.addWidget(h1)
        head.addStretch()
        head.addWidget(self.saved)
        v.addLayout(head)
        sub = QLabel("Switch an account on to manage it, set its limits, then press Apply on that account.")
        sub.setObjectName("muted")
        v.addWidget(sub)
        v.addSpacing(10)
        tiles = QHBoxLayout()
        tiles.setSpacing(14)
        count = lambda x: str(int(round(x)))
        self.a_found = StatTile("Windows accounts", count)
        self.a_managed = StatTile("Managed", count)
        self.a_admins = StatTile("Administrators (never limited)", count)
        for t in (self.a_found, self.a_managed, self.a_admins):
            tiles.addWidget(t)
        v.addLayout(tiles)
        v.addSpacing(10)
        self.acc_note = self._note("")
        v.addWidget(self.acc_note)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        inner = QWidget()
        self.acc_box = QVBoxLayout(inner)
        self.acc_box.setSpacing(14)
        self.acc_box.addStretch()
        sc.setWidget(inner)
        v.addWidget(sc, 1)
        self.refresh_accounts()
        return w

    def _note(self, text):
        l = QLabel(text)
        l.setObjectName("muted")
        l.setWordWrap(True)
        return l

    def _acc_tiles(self):
        managed = sum(1 for n in self.acc_cards if self.cfg["users"].get(n.lower(), {}).get("enabled"))
        self.a_found.animate_to(len(self.acc_cards) + len(self.admins))
        self.a_managed.animate_to(managed)
        self.a_admins.animate_to(len(self.admins))

    def refresh_accounts(self):
        """Windows' account list comes from PowerShell (slow): refresh it in the background."""
        self.flush_save()
        if self._acc_busy:
            return
        self._acc_busy = True
        if not self._acc:
            self.acc_note.setText("Loading accounts…")
        self.run_async(local_accounts, self._accounts_ready)

    def _accounts_ready(self, acc, err):
        self._acc_busy = False
        if err or not acc:
            if not self._acc:
                self.acc_note.setText("Couldn’t read the Windows account list. Administrator accounts "
                                      "are always hidden because they can’t be limited.")
            return  # keep what we already show
        self._acc = acc
        self.flush_save()
        self.admins = {n.lower() for n, a in acc if a}
        gone = [k for k in self.cfg["users"] if k in self.admins]
        for k in gone:  # administrators can never be limited
            del self.cfg["users"][k]
        if gone:
            self.save_cfg()
        names = [n for n, a in acc if not a]
        if names != list(self.acc_cards):
            for c in self.acc_cards.values():
                c.setParent(None)
                c.deleteLater()
            self.acc_cards = {}
            for i, n in enumerate(names):
                c = AccountCard(n, self.save_account)
                c.load(self.cfg["users"].get(n.lower()))
                self.acc_box.insertWidget(self.acc_box.count() - 1, c)
                self.acc_cards[n] = c
                fade_in(c, delay=90 * i)
        self._acc_tiles()
        self.acc_note.setText("")
        self.tick()

    def flush_save(self):
        for c in self.acc_cards.values():
            c.flush()

    def save_account(self, name, v):
        """Called (debounced) by an account card whenever one of its settings changed."""
        key = name.lower()
        if key in self.admins:
            return
        entry = self.cfg["users"].get(key)
        if entry is None and not v["enabled"]:
            return
        was_auto = bool(entry and entry.get("auto_account") and entry.get("enabled") and entry.get("use_schedule"))
        if was_auto and not (v["auto_account"] and v["enabled"] and v["use_schedule"]):
            self.run_async(lambda: run("net", "user", name, "/active:yes"), None)
        u = {**default_user(), **(entry or {})}
        if entry is None and v["enabled"]:  # newly managed account starts with a fresh 24 h balance
            u["credit_min"] = math.ceil(total_used(jload(USE, {}).get(key, {})) / 60) + 1440
        v = dict(v)
        v.pop("idle_shutdown", None)  # legacy: now a PC-wide switch in Settings
        u.update(v)
        for k in ("daily", "daily_min", "bonus_date", "bonus_min", "apps_on", "apps"):  # leftovers
            u.pop(k, None)
        self.cfg["users"][key] = u
        self.save_cfg()
        self.saved.setText("✓  Applied")
        self.saved.setStyleSheet("color:#5FD38D")
        self._saved_anim.stop()
        self._saved_anim.start()
        self._acc_tiles()
        self.tick()

    # ── install requests ──
    def page_requests(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(32, 28, 32, 28)
        head = QHBoxLayout()
        h1 = QLabel("Requests")
        h1.setObjectName("h1")
        head.addWidget(h1)
        head.addStretch()
        clr = QPushButton("Clear answered")
        clr.clicked.connect(self.clear_answered)
        head.addWidget(clr)
        v.addLayout(head)
        v.addWidget(self._note("When a program of a limited user asks Windows for administrator rights, TimeGuard sends "
                               "it here automatically; the user is not asked anything. Nothing is installed until "
                               "you approve it. Approve starts the installer inside the user’s own account with administrator rights; "
                               "Deny tells them no. Check the file path before approving."))
        self.req_note = self._note("")
        v.addWidget(self.req_note)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        inner = QWidget()
        self.req_box = QVBoxLayout(inner)
        self.req_box.setSpacing(12)
        self.req_box.addStretch()
        sc.setWidget(inner)
        v.addWidget(sc, 1)
        self._req_sig = None
        return w

    def refresh_requests(self):
        reqs = list_requests()
        pending = sum(1 for r in reqs if r.get("status") == "pending")
        self.req_nav.setText(f"Requests  ({pending})" if pending else "Requests")
        self.pending = pending
        sig = [(r["id"], r.get("status"), (r.get("launch") or {}).get("state")) for r in reqs]
        if sig == self._req_sig:
            return
        self._req_sig = sig
        while self.req_box.count() > 1:
            it = self.req_box.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        shown = sorted(reqs, key=lambda r: (r.get("status") != "pending", -r.get("ts", 0)))[:60]
        for i, r in enumerate(shown):
            self.req_box.insertWidget(i, RequestRow(r, self.approve_request, self.deny_request))
        self.req_note.setText("" if reqs else "No requests yet.")

    def approve_request(self, r):
        """Approve = start the installer inside the limited user's own session, with administrator rights."""
        path, detected = r.get("path", ""), True
        if not (path and Path(path).is_file()):  # nothing detected (or already deleted): the administrator points to the installer
            detected = False
            path, _ = QFileDialog.getOpenFileName(self, f"Choose the installer for “{r.get('program', '')}”",
                                                  str(Path.home() / "Downloads"), "Installers (*.exe *.msi)")
            if not path:
                return
        self.run_async(lambda: (file_sha256(path), self._signature(path)),
                       lambda res, err: self._approve_ready(r, path, detected, res))

    @staticmethod
    def _signature(path):
        ps = (f"$s=Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39) * 2)}';"
              "$s.Status.ToString()+'|'+$s.SignerCertificate.Subject")
        out = run("powershell", "-NoProfile", "-Command", ps).stdout.strip().split("|", 1)
        return out[0] or "Unknown", (out[1] if len(out) > 1 else "")

    def _approve_ready(self, r, path, detected, res):
        sha, (status, who) = res if res else ("", ("Unknown", ""))
        changed = detected and r.get("sha256") and sha and sha != r["sha256"]
        if changed or status != "Valid":  # only interrupt the administrator when something looks wrong
            text = ("WARNING: this file has CHANGED since the request was made.\n\n" if changed else "")
            text += f"File: {path}\n\nDigital signature: {status}" + (f"\nPublisher: {who}" if who else "")
            if status != "Valid":
                text += "\n\nThis file is not validly signed."
            if QMessageBox.question(self, APP, text + f"\n\nRun it on {r.get('user', '')}’s account anyway?") != QMessageBox.Yes:
                return
        launch = {"path": path, "sha256": sha, "state": "queued", "ts": time.time()}
        if not decide_request(r["id"], "approved", "It is starting now.", launch):
            QMessageBox.information(self, APP, "This request was already answered.")
        self.refresh_requests()

    def deny_request(self, r):
        note, ok = QInputDialog.getText(self, APP, f"Deny “{r.get('program', '')}”. Message for the user (optional):")
        if ok:
            decide_request(r["id"], "denied", note)
            self.refresh_requests()

    def clear_answered(self):
        for r in list_requests():
            if r.get("status") != "pending":
                try:
                    (REQ / f"{r['id']}.json").unlink()
                except OSError:
                    pass
        self.refresh_requests()

    # ── settings ──
    def page_settings(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(32, 28, 32, 28)
        v.setSpacing(14)
        h1 = QLabel("Settings")
        h1.setObjectName("h1")
        v.addWidget(h1)
        card = QFrame()
        card.setObjectName("card")
        cv = QVBoxLayout(card)
        cv.setContentsMargins(24, 20, 24, 20)
        cv.setSpacing(10)
        h2 = QLabel("Protection")
        h2.setObjectName("h2")
        cv.addWidget(h2)
        self.prot = QLabel()
        cv.addWidget(self.prot)
        cv.addWidget(self._note("The background service counts time and enforces limits, even when this window is closed. "
                                "Standard users cannot stop or edit it. It is installed / repaired by UPDATE and removed by "
                                "Remove service (WoL Host > This PC > Actions)."))
        v.addWidget(card)
        card2 = QFrame()
        card2.setObjectName("card")
        c2 = QVBoxLayout(card2)
        c2.setContentsMargins(24, 20, 24, 20)
        c2.setSpacing(10)
        h3 = QLabel("Admin password")
        h3.setObjectName("h2")
        c2.addWidget(h3)
        c2.addWidget(self._note("Ask for a password whenever TimeGuard is opened."))
        pw = QPushButton("Set / change password")
        pw.clicked.connect(self.set_pw)
        c2.addWidget(pw, 0, Qt.AlignLeft)
        v.addWidget(card2)
        card4 = QFrame()
        card4.setObjectName("card")
        c4 = QVBoxLayout(card4)
        c4.setContentsMargins(24, 20, 24, 20)
        c4.setSpacing(10)
        h5 = QLabel("Install requests")
        h5.setObjectName("h2")
        c4.addWidget(h5)
        self.req_on = Toggle("Forward admin requests of limited users to me")
        self.req_on.setChecked(bool(self.cfg.get("install_requests", True)))
        self.req_on.toggled.connect(self._set_req)
        c4.addWidget(self.req_on)
        c4.addWidget(self._note("Programs of limited users that ask for administrator rights are sent to the Requests page, "
                                "and are closed so the user cannot type a password."))
        self.uac_on = Toggle("Close Windows’ admin prompt for limited users (they can’t type a password)")
        self.uac_on.setChecked(bool(self.cfg.get("uac_block", True)))
        self.uac_on.toggled.connect(self._set_uac)
        c4.addWidget(self.uac_on)
        c4.addWidget(self._note("Off: the request is still sent, but the normal Windows prompt stays open, so an "
                                "administrator standing at the PC can type their password instead."))
        v.addWidget(card4)
        card6 = QFrame()
        card6.setObjectName("card")
        c6 = QVBoxLayout(card6)
        c6.setContentsMargins(24, 20, 24, 20)
        c6.setSpacing(10)
        h7 = QLabel("Sign-in screen")
        h7.setObjectName("h2")
        c6.addWidget(h7)
        self.idle_on = Toggle("Shut the PC down when the sign-in screen sits unused for 5 minutes")
        self.idle_on.setChecked(bool(self.cfg.get("idle_shutdown", False)))
        self.idle_on.toggled.connect(self._set_idle_shutdown)  # connected after setChecked: loading is not a change
        c6.addWidget(self.idle_on)
        c6.addWidget(self._note("One switch for the whole PC (all users): when nobody is signed in and the Windows sign-in screen has been "
                                "idle for 5 minutes, the PC shuts down after a 30-second warning. Any signed-in, locked or "
                                "disconnected user counts as someone being there."))
        v.addWidget(card6)
        card5 = QFrame()
        card5.setObjectName("card")
        c5 = QVBoxLayout(card5)
        c5.setContentsMargins(24, 20, 24, 20)
        c5.setSpacing(10)
        h6 = QLabel("Startup")
        h6.setObjectName("h2")
        c5.addWidget(h6)
        self.auto_on = Toggle("Start TimeGuard automatically when I sign in to Windows")
        self.auto_on.setChecked(bool(self.cfg.get("autostart", False)))
        self.auto_on.toggled.connect(self._set_autostart)  # connected after setChecked: loading is not a change
        c5.addWidget(self.auto_on)
        c5.addWidget(self._note("TimeGuard then starts minimized in the tray, with administrator rights and without "
                                "a Windows prompt. Closing the window with ✕ also only minimizes it to the tray; "
                                "use the tray icon’s Quit to really close it. Limits are enforced by the background "
                                "protection either way."))
        v.addWidget(card5)
        if self.EMBED:  # docked inside WoL Host: there is no separate tray window to start with Windows
            card5.hide()
        else:
            self.run_async(autostart_exists, self._autostart_synced)  # show what Windows really has
        v.addStretch()
        sc = QScrollArea()  # the page is taller than the window: scroll instead of squeezing the cards
        sc.setWidgetResizable(True)
        sc.setWidget(w)
        return sc

    def _set_idle_shutdown(self, on):
        self.cfg["idle_shutdown"] = bool(on)
        self.save_cfg()

    def _set_uac(self, on):
        self.cfg["uac_block"] = bool(on)
        self.save_cfg()

    def _set_req(self, on):
        self.cfg["install_requests"] = bool(on)
        self.save_cfg()

    def _autostart_synced(self, exists, err):
        if err or exists is None:
            return
        self.auto_on.blockSignals(True)
        self.auto_on.setChecked(bool(exists))
        self.auto_on.blockSignals(False)
        self.cfg["autostart"] = bool(exists)

    def _set_autostart(self, on):
        self.auto_on.setEnabled(False)

        def done(problem, err):
            self.auto_on.setEnabled(True)
            msg = problem or (str(err) if err else "")
            if msg:  # did not work: put the switch back
                self.auto_on.blockSignals(True)
                self.auto_on.setChecked(not on)
                self.auto_on.blockSignals(False)
                QMessageBox.warning(self, APP, "Could not change the startup setting:\n" + msg)
            else:
                self.cfg["autostart"] = bool(on)
                self.save_cfg()
        self.run_async(lambda: set_autostart(on), done)

    def set_pw(self):
        pw, ok = QInputDialog.getText(self, APP, "New password (leave empty to remove):", QLineEdit.Password)
        if not ok:
            return
        if pw:
            salt = secrets.token_hex(16)
            self.cfg["pw"] = {"salt": salt, "hash": hash_pw(pw, salt)}
        else:
            self.cfg.pop("pw", None)
        self.save_cfg()


def authenticate(cfg, parent=None):
    pw = cfg.get("pw")
    if not pw:
        return True
    for _ in range(3):
        text, ok = QInputDialog.getText(parent, APP, "Admin password:", QLineEdit.Password)
        if not ok:
            return False
        if secrets.compare_digest(hash_pw(text, pw["salt"]), pw["hash"]):
            return True
    return False


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


def elevate():
    import ctypes
    args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                        " ".join(f'"{a}"' for a in args), None, 1)


def run_gui():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    app.setQuitOnLastWindowClosed(False)  # the program lives in the tray; it ends with "Quit" in the tray menu
    name = "TimeGuardAdminWindow"
    probe = QLocalSocket()  # already running (e.g. started with Windows, sitting in the tray)? Ask it to open and stop
    probe.connectToServer(name)
    if probe.waitForConnected(300):
        probe.write(b"show\n")
        probe.waitForBytesWritten(500)
        probe.disconnectFromServer()
        sys.exit(0)
    to_tray = "--tray" in sys.argv  # started with Windows: stay hidden in the tray until the user opens it
    if not to_tray and not authenticate(jload(CFG, {})):
        sys.exit(0)
    win = Main()
    win._authed = not to_tray
    app.commitDataRequest.connect(lambda *_: setattr(win, "_quit", True))  # Windows sign-out/shutdown must not be blocked
    QLocalServer.removeServer(name)
    server = QLocalServer(win)
    server.listen(name)
    server.newConnection.connect(lambda: (server.nextPendingConnection(), win.reveal()))
    if to_tray and win.tray is None:
        to_tray = False  # no tray on this system: a hidden window could never be reopened
        win._authed = authenticate(jload(CFG, {}))
        if not win._authed:
            sys.exit(0)
    if not to_tray:
        win.setWindowOpacity(0.0)
        win.show()
        anim = QPropertyAnimation(win, b"windowOpacity", win)
        anim.setDuration(380)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start()
    else:
        win.setWindowOpacity(1.0)
    sys.exit(app.exec())


def _adopt_window(hwnd, parent):
    """Turn this process's top-level window into a child of a window that belongs to another process.
    Returns "child" (really docked), "owner" (could not dock: it stays a borderless window that the host keeps
    positioned over the tab) or "none"."""
    import ctypes
    from ctypes import wintypes as w
    u = ctypes.windll.user32
    getl = getattr(u, "GetWindowLongPtrW", None) or u.GetWindowLongW
    setl = getattr(u, "SetWindowLongPtrW", None) or u.SetWindowLongW
    getl.argtypes, getl.restype = [w.HWND, ctypes.c_int], ctypes.c_ssize_t
    setl.argtypes, setl.restype = [w.HWND, ctypes.c_int, ctypes.c_ssize_t], ctypes.c_ssize_t
    u.SetParent.argtypes, u.SetParent.restype = [w.HWND, w.HWND], w.HWND
    u.SetWindowPos.argtypes = [w.HWND, w.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    GWL_STYLE, GWL_EXSTYLE, GWLP_HWNDPARENT = -16, -20, -8
    CHROME = 0x00C00000 | 0x00040000 | 0x00080000 | 0x00020000 | 0x00010000  # caption, sizing frame, sysmenu, min, max
    WS_POPUP, WS_CHILD, CLIP = 0x80000000, 0x40000000, 0x04000000 | 0x02000000
    saved = getl(hwnd, GWL_STYLE) & 0xFFFFFFFF
    # MSDN: when a top-level window becomes a child, set WS_CHILD (and drop WS_POPUP) BEFORE calling SetParent
    setl(hwnd, GWL_STYLE, (saved & ~(CHROME | WS_POPUP)) | WS_CHILD | CLIP)
    u.GetParent.argtypes, u.GetParent.restype = [w.HWND], w.HWND
    ctypes.set_last_error(0)
    u.SetParent(hwnd, parent)
    # SetParent returns the PREVIOUS parent, which is NULL for a top-level window - so its return value cannot tell
    # success from failure (that made docking look like it failed and TimeGuard opened as a separate window).
    # Ask Windows who the parent is now instead.
    if (u.GetParent(hwnd) or 0) == (parent or 0):
        u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x37)  # NOSIZE | NOMOVE | NOZORDER | NOACTIVATE | FRAMECHANGED
        return "child"
    print(f"TimeGuard: SetParent failed (Windows error {ctypes.get_last_error() or ctypes.GetLastError()})", flush=True)
    # Docking was refused (for example because the two programs use different DPI modes): keep a borderless popup
    # that is OWNED by the host window (stays above it, minimizes with it, hidden from the taskbar).
    setl(hwnd, GWL_STYLE, (saved & ~CHROME) | WS_POPUP)
    setl(hwnd, GWLP_HWNDPARENT, parent)
    setl(hwnd, GWL_EXSTYLE, (getl(hwnd, GWL_EXSTYLE) & ~0x00040000) | 0x00000080)  # no WS_EX_APPWINDOW, add TOOLWINDOW
    u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x37)
    return "owner"


def _adopt_qt(win, parent_hwnd):
    """Dock with Qt's own foreign-window support (QWindow.setParent) - Qt then keeps its internal window state in step with
    Windows, which the raw SetParent call below cannot. Returns True when Windows reports the new parent."""
    import ctypes
    from ctypes import wintypes as w
    try:
        from PySide6.QtGui import QWindow
        win.winId()                                   # make sure the native window exists
        foreign = QWindow.fromWinId(parent_hwnd)
        win._foreign = foreign                        # keep it alive as long as the window
        win.windowHandle().setParent(foreign)
        u = ctypes.windll.user32
        u.GetParent.argtypes, u.GetParent.restype = [w.HWND], w.HWND
        ok = (u.GetParent(int(win.winId())) or 0) == parent_hwnd
        if not ok:
            print("TimeGuard: Qt docking did not take effect", flush=True)
        return ok
    except Exception as e:
        print(f"TimeGuard: Qt docking failed: {e!r}", flush=True)
        return False


def make_embedded(parent):
    """The admin window as an ordinary CHILD WIDGET of `parent` - same process, same Qt event loop (used by WoL Host's own Qt window).
    Nothing is docked with the Windows API, so it can never turn into a separate window. The caller places/shows/hides it."""
    Main.EMBED = True
    win = Main()
    win.setParent(parent, Qt.Widget)
    return win


def run_embedded(parent_hwnd, info_path):
    """The admin window docked into another program's window (the TimeGuard tab of WoL Host).
    This process writes {pid, hwnd, mode} (or {error}) to info_path; the host then moves, shows and hides the window.
    The host asks it to end by creating info_path + ".quit" (or by closing its own window)."""
    import ctypes
    info, quitf = Path(info_path), Path(str(info_path) + ".quit")
    if os.name == "nt" and os.environ.get("TG_DPI_CTX"):  # same DPI context as the host window, or Windows refuses to dock
        try:
            ok = ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(int(os.environ["TG_DPI_CTX"])))
            print(f"TimeGuard: DPI context {os.environ['TG_DPI_CTX']} applied: {bool(ok)}", flush=True)
        except Exception as e:
            print(f"TimeGuard: could not set the DPI context: {e!r}", flush=True)

    def report(**kw):
        try:
            jsave(info, dict(pid=os.getpid(), **kw))
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    probe = QLocalSocket()  # a stand-alone TimeGuard (e.g. from an older start-with-Windows entry) would write the same files
    probe.connectToServer("TimeGuardAdminWindow")
    if probe.waitForConnected(300):
        probe.disconnectFromServer()
        report(error="TimeGuard is already open in its own window or in the tray. Quit it there "
                     "(right-click the tray icon, Quit), then open this tab again.")
        sys.exit(0)
    if not authenticate(jload(CFG, {})):
        report(error="TimeGuard is locked: the admin password was not entered.", locked=True)
        sys.exit(0)
    Main.EMBED = True
    win = Main()
    win.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
    win.resize(1000, 640)
    hwnd = int(win.winId())
    mode = "none"
    if os.name == "nt":
        try:
            if _adopt_qt(win, parent_hwnd):
                mode = "child"
                hwnd = int(win.winId())
            else:
                hwnd = int(win.winId())
                mode = _adopt_window(hwnd, parent_hwnd)
                print(f"TimeGuard: raw docking result: {mode}", flush=True)
        except Exception as e:
            report(error=f"Could not dock the window: {e}")
            sys.exit(1)
    win.show()
    if os.name == "nt":
        ctypes.windll.user32.ShowWindow(ctypes.c_void_p(hwnd), 0)  # stays hidden until the host puts it on the tab
    report(hwnd=hwnd, mode=mode)

    pagef = Path(str(info_path) + ".page")

    def watch():
        try:
            if pagef.exists():
                n = int(pagef.read_text().strip() or 0)
                pagef.unlink()
                win.go(max(0, min(n, win.stack.count() - 1)))
        except Exception:
            pass
        gone = os.name == "nt" and not ctypes.windll.user32.IsWindow(ctypes.c_void_p(parent_hwnd))
        if gone or quitf.exists():
            win._quit = True
            win.close()
            app.quit()
    t = QTimer(win)
    t.timeout.connect(watch)
    t.start(500)
    code = app.exec()
    try:
        quitf.unlink()
    except OSError:
        pass
    sys.exit(code)


if __name__ == "__main__":
    if "--agent" in sys.argv or "--tg-agent" in sys.argv:
        run_agent()
    elif "--tg-idle" in sys.argv:
        run_idle()
    elif os.name == "nt" and not is_admin():
        elevate()
    else:
        run_gui()
'''
# ============================ end of embedded TimeGuard ============================


if "--agent" in sys.argv: agent()
elif any(f in sys.argv for f in ("--tg-engine", "--tg-agent", "--tg-pad", "--tg-idle", "--tg-gui")): tg_main()
elif "--move-data" in sys.argv:
    if os.name == "nt" and not is_admin(): print("Run this as administrator."); sys.exit(1)
    _ok, _m = use_data_drive(); log(f"move-data: {_ok} {_m}"); print(("OK: " if _ok else "FAILED: ") + _m)
    if _ok: sh("schtasks /delete /tn WoLHostMoveData /f", 20); sh("schtasks /run /tn WoLHostAgent", 20)          # done: no boot task needed any more, start the agent again
    sys.exit(0 if _ok else 1)
elif "--primeinput" in sys.argv: primeinput_main()
elif "--sunlaunch" in sys.argv: sun_launch_main()
elif "--typepin" in sys.argv:
    _i = sys.argv.index("--typepin"); _a = sys.argv[_i + 1:]
    typepin_main(_a[0], _a[1] if len(_a) > 1 else "pin", len(_a) > 2 and _a[2] == "watch", _a[3] if len(_a) > 3 else "")
else:
    if os.name == "nt" and not is_admin():       # relaunch elevated
        args = " ".join(sys.argv[1:]) if getattr(sys, "frozen", False) else " ".join([f'"{os.path.abspath(__file__)}"'] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1); sys.exit()
    if "--classic" in sys.argv: run_gui()
    elif "--webview2" in sys.argv: run_web_gui() or run_gui()      # old window: TimeGuard is docked into it from a second process
    elif not (run_qt_gui() or run_web_gui()): run_gui()
