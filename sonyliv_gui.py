#!/usr/bin/env python3
"""
SonyLIV Downloader GUI
======================
Tabs: Login | Download | Settings
Auth: Phone OTP → JWT Bearer token (no cookies)
DRM:  N_m3u8DL-RE + device.wvd (Widevine)
Non-DRM: N_m3u8DL-RE or yt-dlp
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, subprocess, json, os, re, sys, time, hashlib, uuid, base64
import urllib.request, urllib.parse
from pathlib import Path
from datetime import datetime, timezone

_UA  = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
_HEADERS = {
    "content-type": "application/json",
    "user-agent":   _UA,
    "origin":       "https://www.sonyliv.com",
    "referer":      "https://www.sonyliv.com/",
}
_SERIAL = f"{uuid.uuid4().hex}-{int(time.time()*1000)}"

def _now_iso():
    n = datetime.now(timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond//1000:03d}Z"

def _decode_jwt(token):
    try:
        p = token.split(".")[1]; p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}

def _api_post(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers=_HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

def sony_send_otp(mobile: str) -> dict:
    """POST CREATEOTP-V2 → returns full response dict."""
    return _api_post(
        "https://apiv2.sonyliv.com/AGL/1.6/A/ENG/WEB/IN/MH/CREATEOTP-V2",
        {
            "mobileNumber":    mobile,
            "channelPartnerID":"MSMIND",
            "country":         "IN",
            "timestamp":       _now_iso(),
            "otpSize":         4,
            "loginType":       "REGISTERORSIGNIN",
            "isMobileMandatory": True,
        }
    )

def sony_verify_otp(mobile: str, otp: str) -> dict:
    """POST CONFIRMOTP-V2 → returns full response dict with accessToken."""
    return _api_post(
        "https://apiv2.sonyliv.com/AGL/2.4/A/ENG/WEB/IN/MH/CONFIRMOTP-V2",
        {
            "channelPartnerID":  "MSMIND",
            "mobileNumber":      mobile,
            "country":           "IN",
            "otp":               otp,
            "dmaId":             "IN",
            "ageConfirmation":   True,
            "timestamp":         _now_iso(),
            "isMobileMandatory": True,
            "deviceDetails": {
                "deviceName": "NA",
                "deviceType": "webClient",
                "gaUserId":   f"GA1.2.{abs(hash(mobile)) % 2000000000}.{int(time.time())}",
                "modelNo":    "Chrome Browser",
                "serialNo":   _SERIAL,
            },
            "address":         {"state": "MH"},
            "checkDeviceLimit": True,
        }
    )

# Visible browser only - Sony's bot detection blocks headless CDP automation.
# Two capture paths (network + localStorage) so a tab refresh doesn't lose the token.

_JS_GET_TOKEN = """
() => {
    const keys = ['userToken','accessToken','token','userInfo','userData',
                  'SonyLIVUser','persist:root','msm_user'];
    for (const k of keys) {
        try {
            const v = localStorage.getItem(k);
            if (!v) continue;
            if (v.startsWith('eyJ')) return JSON.stringify({accessToken: v});
            const obj = JSON.parse(v);
            if (obj && obj.accessToken) return JSON.stringify(obj);
            if (obj && obj.token)       return JSON.stringify({accessToken: obj.token});
            if (obj && typeof obj === 'object') {
                const s = JSON.stringify(obj);
                const m = s.match(/"accessToken"\\s*:\\s*"(eyJ[^"]+)"/);
                if (m) return JSON.stringify({accessToken: m[1]});
            }
        } catch(e) {}
    }
    try {
        for (let i = 0; i < sessionStorage.length; i++) {
            const v = sessionStorage.getItem(sessionStorage.key(i));
            if (v && v.includes('accessToken')) {
                const m = v.match(/"accessToken"\\s*:\\s*"(eyJ[^"]+)"/);
                if (m) return JSON.stringify({accessToken: m[1]});
            }
        }
    } catch(e) {}
    return null;
}
"""

def _pw_run_manual(result_holder: list, log_cb, cancel_flag: list):
    """
    Opens sonyliv.com in a VISIBLE browser. Chief logs in himself.
    Two parallel capture methods:
      1. Network sniffer - catches CONFIRMOTP response (most reliable)
      2. localStorage poller every 1s - catches token even if tab was refreshed
    result_holder[0] = {"token_data": td} on success, {"error": "..."} on failure.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log_cb("[PW] playwright not installed - run: pip install playwright && python -m playwright install chrome")
        result_holder[0] = {"error": "playwright_missing"}
        return

    log_cb("[PW] Opening browser - log in manually, token will be grabbed automatically")
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(
                channel="chrome",
                headless=False,
                args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--exclude-switches=enable-automation",
                    "--start-maximized",
                ],
            )
            log_cb("[PW] Using system Chrome")
        except Exception:
            try:
                browser = pw.chromium.launch(
                    headless=False,
                    args=[
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--start-maximized",
                    ],
                )
                log_cb("[PW] Using Playwright Chromium")
            except Exception as ex:
                log_cb(f"[PW] Browser launch failed: {ex}")
                result_holder[0] = {"error": str(ex)}
                return

        ctx = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/137.0.0.0 Safari/537.36"
            ),
            viewport=None,   # maximized - no fixed viewport
            locale="en-US",
        )
        # Minimal stealth: only kill the webdriver flag - more patches increase fingerprint deviation
        ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        )

        captured = {}
        def on_response(resp):
            url = resp.url
            if "CONFIRMOTP" in url.upper():
                try:
                    body = resp.json()
                    ro   = body.get("resultObj", {})
                    if ro.get("accessToken"):
                        captured["result"] = ro
                        log_cb("[PW] ✓ Token captured from network!")
                    else:
                        log_cb(f"[NET] CONFIRMOTP - no token: {ro.get('message','')}")
                except Exception as ex:
                    log_cb(f"[NET] CONFIRMOTP parse err: {ex}")

        ctx.on("response", on_response)
        page = ctx.new_page()

        log_cb("[PW] Loading sonyliv.com …")
        try:
            page.goto("https://www.sonyliv.com/", wait_until="domcontentloaded", timeout=25000)
        except Exception as ex:
            log_cb(f"[PW] Navigation error: {ex}")
            result_holder[0] = {"error": str(ex)}
            browser.close(); return

        log_cb("[PW] ✅ Browser ready - please log in. Token will save automatically.")

        deadline     = time.time() + 300
        ls_last_poll = 0.0
        while time.time() < deadline:
            if cancel_flag[0]:
                log_cb("[PW] Cancelled by user")
                browser.close(); return

            if captured.get("result"):
                break

            # fallback: localStorage every 1s (survives tab refresh)
            if time.time() - ls_last_poll >= 1.0:
                ls_last_poll = time.time()
                try:
                    for pg in ctx.pages:
                        try:
                            raw = pg.evaluate(_JS_GET_TOKEN)
                            if raw:
                                obj = json.loads(raw)
                                tok = obj.get("accessToken", "")
                                if tok and tok.startswith("eyJ"):
                                    log_cb("[PW] ✓ Token found in localStorage!")
                                    captured["ls_token"] = tok
                                    break
                        except Exception:
                            pass
                except Exception:
                    pass

            if captured.get("ls_token"):
                break

            time.sleep(0.3)
        else:
            log_cb("[PW] ✗ Timed out (5 min) - no token found")
            result_holder[0] = {"error": "login_timeout"}
            browser.close(); return

        browser.close()

        if captured.get("result"):
            ro    = captured["result"]
            token = ro.get("accessToken", "")
            src   = "network"
        else:
            token = captured.get("ls_token", "")
            ro    = {}
            src   = "localStorage"

        log_cb(f"[PW] Source: {src} | token: {token[:40]}…")
        jwt    = _decode_jwt(token)
        mobile = jwt.get("mobileNumber", ro.get("mobileNumber", ""))
        td = {
            "access_token":   token,
            "contact_id":     str(jwt.get("contactID",  ro.get("contactId",  ""))),
            "cp_customer_id": ro.get("cpCustomerID",     jwt.get("userId",    "")),
            "mobile":         mobile,
            "first_name":     jwt.get("firstName",  "") or ro.get("firstName",  ""),
            "last_name":      jwt.get("lastName",   "") or ro.get("lastName",   ""),
            "is_subscribed":  ro.get("isSubscribed",      False),
            "is_new_user":    ro.get("isNewRegistration", False),
            "device_id":      ro.get("deviceId", ""),
            "inner_token":    jwt.get("token", ""),
            "saved_at":       _now_iso(),
            "expires_at":     jwt.get("expirationMoment", ""),
        }
        result_holder[0] = {"token_data": td}
        name = (td["first_name"] + " " + td["last_name"]).strip() or "?"
        log_cb(f"[PW] ✓ Logged in as {name} | +91{mobile} | subscribed={td['is_subscribed']}")


# --- colours
BG      = "#0d0f18"
BG2     = "#13151f"
BG3     = "#1c1e2e"
BG4     = "#22253a"
ACC     = "#7c6af7"
ACC2    = "#5a48e0"
ACC3    = "#a599ff"
FG      = "#e4e4f0"
FG2     = "#7a7a9d"
FG3     = "#44445a"
RED     = "#f87171"
GREEN   = "#4ade80"
GRN     = "#4ade80"
YLW     = "#fbbf24"
ORG     = "#fb923c"
FONT    = ("Segoe UI", 10)
FONTB   = ("Segoe UI", 10, "bold")
FONTL   = ("Segoe UI", 9)
MONO    = ("Consolas", 10)

CFG_FILE = Path.home() / ".sonyliv_downloader.json"

_ACTIVE_TOKEN: dict = {}

def _set_active_token(token_data: dict) -> None:
    """Called by GUI when user loads/reloads token - makes it available globally."""
    global _ACTIVE_TOKEN
    _ACTIVE_TOKEN = token_data or {}

def _get_access_token() -> str:
    """Return Bearer token from active session, or '' if not loaded."""
    return _ACTIVE_TOKEN.get("access_token", "")

DEFAULT_CFG = {
    "token_file":      str(Path.home() / ".sonyliv_token.json"),
    "output_dir":      str(Path.home() / "Downloads" / "SonyLIV"),
    "n_m3u8dl_exe":   "N_m3u8DL-RE",
    "ytdlp_exe":       "yt-dlp",
    "ffmpeg_exe":      "ffmpeg",
    "wvd_file":        "",
    "shaka_exe":       "shaka-packager",
    "mp4decrypt_exe":  "mp4decrypt",
    "mkvmerge_exe":    "mkvmerge",
    "thread_count":    32,               # N_m3u8DL-RE --thread-count (default 32)
    "engine":          "N_m3u8DL-RE",   # N_m3u8DL-RE | yt-dlp | ffmpeg
    "drm_tool":        "auto",           # auto | mp4decrypt | shaka
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/137.0.0.0 Safari/537.36")

def load_cfg():
    if CFG_FILE.exists():
        try:
            d = json.loads(CFG_FILE.read_text())
            cfg = DEFAULT_CFG.copy(); cfg.update(d); return cfg
        except: pass
    return DEFAULT_CFG.copy()

def save_cfg(cfg):
    CFG_FILE.write_text(json.dumps(cfg, indent=2))

# --- SonyLIV API helpers
def extract_content_id(url: str) -> str:
    """
    Pull the episode/content ID from a SonyLIV URL.
    URL patterns:
      /shows/series-name-{seriesId}/episode-title-{contentId}?watch=true
      /movies/movie-title-{contentId}?watch=true
    We always want the LAST numeric segment in the path (before ?).
    """
    # strip query string
    path = url.split("?")[0].rstrip("/")
    # find all numeric segments of 7-12 digits in the path
    nums = re.findall(r'(?<!\d)(\d{7,12})(?!\d)', path)
    if nums:
        return nums[-1]   # last one = content/episode ID
    # fallback: direct numeric id
    m = re.search(r'(\d{7,12})', url)
    return m.group(1) if m else ""

def resolve_playable_id(bundle_id: str, contact_id: str, device_id: str,
                        cookies: dict, cluster: str = "TG", log_cb=None) -> tuple:
    """
    SonyLIV uses a two-level ID system:
      - bundle_id  : page/bundle ID in the URL  (e.g. 1500004612 / 1590016456)
      - playable_id: actual streamable asset ID  (e.g. 1000188659 / 1090539851)

    Resolution strategy (three attempts in order):
    1. USER/SUGGESTION API  → resultObj.suggestions.ctas[].button_cta = "sony://asset/<id>"
                               title from ctas[].overlay_content_title
    2. DETAIL-V2 API        → resultObj.containers[].id where layout="CONTENT_ITEM"
                               title from containers[].metadata.title
    3. Fallback             → use bundle_id as-is (might be already playable)

    Returns (playable_id: str, title: str, duration_ms: int)
    """
    import re as _re

    # Load bearer token for auth (SUGGESTION needs it for user-specific data)
    access_token = _get_access_token()

    contact_param = f"?contactId={contact_id}" if contact_id and contact_id != "0" else ""
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _get(url, hdrs):
        """GET helper - requests first, urllib fallback."""
        try:
            import requests as _req
            r = _req.get(url, headers=hdrs, timeout=10)
            return r.json()
        except ImportError:
            pass
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def _extract_asset_id(text: str):
        """Pull numeric ID from sony://asset/<id> deep link."""
        m = _re.search(r'sony://asset/(\d+)', text)
        return m.group(1) if m else None

    base_headers = {
        "accept":          "application/json, text/plain, */*",
        "app_version":     "3.6.83",
        "device_id":       device_id,
        "advertiserid":    device_id,
        "session_id":      hashlib.md5(str(uuid.uuid4()).encode()).hexdigest() + f"-{int(time.time()*1000)}",
        "origin":          "https://www.sonyliv.com",
        "referer":         "https://www.sonyliv.com/",
        "user-agent":      UA,
        "x-via-device":    "true",
        "cookie":          cookie_str,
    }
    if access_token:
        base_headers["authorization"] = f"Bearer {access_token}"

    _resolved_dur_ms = [0]   # mutable container so inner funcs can write it

    def _detail_v2_title(lookup_id: str) -> str:
        """Pull title + duration from DETAIL-V2. Returns '' on failure."""
        for cl2 in [cluster, "TG", "KL", "AP"]:
            api2 = (f"https://apiv3.sonyliv.com/AGL/4.8/SR/ENG/WEB/IN/{cl2}"
                    f"/DETAIL-V2/{lookup_id}?kids_safe=false&from=0&to=9"
                    f"&segment_id=AB_DetailPage_Disable")
            try:
                d2 = _get(api2, base_headers)
                containers = d2.get("resultObj", {}).get("containers", [])
                for c in containers:
                    meta = c.get("metadata", {})
                    t = (meta.get("title","") or meta.get("episodeTitle","") or
                         meta.get("contentName","") or "")
                    dur_s = meta.get("duration", 0)
                    if dur_s and not _resolved_dur_ms[0]:
                        _resolved_dur_ms[0] = int(dur_s) * 1000
                    # Also dig one level deeper for nested containers
                    for cc in c.get("containers", []):
                        cmeta = cc.get("metadata", {})
                        dur_s2 = cmeta.get("duration", 0)
                        if dur_s2 and not _resolved_dur_ms[0]:
                            _resolved_dur_ms[0] = int(dur_s2) * 1000
                    if t:
                        return t
            except Exception:
                pass
        return ""

    # --- Strategy 1: USER/SUGGESTION
    _seen_sg = {}
    for cl in [cluster, "TG", "KL", "MH", "AP", "TN"]:
        api = (f"https://apiv2.sonyliv.com/AGL/3.4/SR/ENG/WEB/IN/{cl}"
               f"/USER/SUGGESTION/{bundle_id}{contact_param}")
        try:
            data = _get(api, base_headers)
            suggestions = data.get("resultObj", {}).get("suggestions", {})
            _cdur = suggestions.get("content_duration", 0)
            if _cdur and not _resolved_dur_ms[0]:
                _resolved_dur_ms[0] = int(_cdur)
            for cta in suggestions.get("ctas", []):
                pid = _extract_asset_id(cta.get("button_cta","") or cta.get("button_sub_cta",""))
                if pid and pid != bundle_id:
                    _title = (cta.get("overlay_content_title","") or
                              cta.get("button_title","") or "")
                    # overlay_content_title can be empty for some movies -
                    # fall back to DETAIL-V2 on the resolved pid
                    if not _title:
                        _title = _detail_v2_title(pid) or _detail_v2_title(bundle_id)
                    if log_cb: log_cb(f"[✓] Resolved {bundle_id} → {pid} via SUGGESTION (cluster={cl})"
                                      + (f" | title: {_title}" if _title else ""))
                    return pid, _title, _resolved_dur_ms[0]
            # Top-level button_cta: present when ctas[] is empty or all ctas share the bundle_id
            pid = _extract_asset_id(suggestions.get("button_cta",""))
            if pid and pid != bundle_id:
                # Try ctas[] for title first (sometimes present even here)
                _title = ""
                for cta in suggestions.get("ctas", []):
                    _title = (cta.get("overlay_content_title","") or
                              cta.get("button_sub_title","") or "")
                    if _title:
                        break
                if not _title:
                    _title = _detail_v2_title(pid) or _detail_v2_title(bundle_id)
                if log_cb: log_cb(f"[✓] Resolved {bundle_id} → {pid} via SUGGESTION top-level (cluster={cl})"
                                  + (f" | title: {_title}" if _title else ""))
                return pid, _title, _resolved_dur_ms[0]
            if data.get("resultCode") != "OK":
                err_sg = data.get("errorDescription","") or data.get("message","")
                if err_sg and err_sg not in _seen_sg:
                    _seen_sg[err_sg] = cl
                    if log_cb: log_cb(f"[DBG/SUGGESTION/{cl}] code={data.get('resultCode')} err={err_sg!r}")
        except Exception as ex:
            _seen_sg[str(ex)] = cl
            if log_cb: log_cb(f"[DBG/SUGGESTION/{cl}] exception: {ex}")

    # --- Strategy 2: DETAIL-V2 → containers with layout=CONTENT_ITEM
    if log_cb: log_cb(f"[...] SUGGESTION failed (unique errors: {list(_seen_sg.items())[:3]}) - trying DETAIL-V2 for {bundle_id}")
    for cl in [cluster, "TG", "KL", "AP"]:
        api = (f"https://apiv3.sonyliv.com/AGL/4.8/SR/ENG/WEB/IN/{cl}"
               f"/DETAIL-V2/{bundle_id}?kids_safe=false&from=0&to=9"
               f"&segment_id=AB_DetailPage_Disable")
        try:
            data = _get(api, base_headers)
            containers = data.get("resultObj", {}).get("containers", [])
            for c in containers:
                meta = c.get("metadata", {})
                # Try CONTENT_ITEM layout first (most reliable)
                # Grab duration from this container's metadata
                dur_s = meta.get("duration", 0)
                if dur_s and not _resolved_dur_ms[0]:
                    _resolved_dur_ms[0] = int(dur_s) * 1000
                for cc in c.get("containers", []):
                    dur_s2 = cc.get("metadata", {}).get("duration", 0)
                    if dur_s2 and not _resolved_dur_ms[0]:
                        _resolved_dur_ms[0] = int(dur_s2) * 1000
                if c.get("layout") == "CONTENT_ITEM":
                    cid = str(c.get("id","") or c.get("contentId","") or meta.get("contentId",""))
                    if cid and cid != bundle_id:
                        _title = (meta.get("title","") or meta.get("episodeTitle","") or
                                  meta.get("contentName","") or "")
                        if log_cb: log_cb(f"[✓] Resolved {bundle_id} → {cid} via DETAIL-V2 (cluster={cl})"
                                          + (f" | title: {_title}" if _title else ""))
                        return cid, _title, _resolved_dur_ms[0]
                # Also search nested metadata.contentId (movies use this instead of layout=CONTENT_ITEM)
                cid = str(meta.get("contentId","") or meta.get("id",""))
                if cid and cid.isdigit() and cid != bundle_id and int(cid) > 0:
                    _title = (meta.get("title","") or meta.get("episodeTitle","") or "")
                    if log_cb: log_cb(f"[✓] Resolved {bundle_id} → {cid} via DETAIL-V2 metadata (cluster={cl})"
                                      + (f" | title: {_title}" if _title else ""))
                    return cid, _title, _resolved_dur_ms[0]
        except Exception as ex:
            if log_cb: log_cb(f"[DEBUG] DETAIL-V2/{cl} error: {ex}")

    if log_cb: log_cb(f"[!] Could not resolve playable ID for {bundle_id} - using as-is")
    return bundle_id, "", _resolved_dur_ms[0]


def load_token(path: str) -> dict:
    """Load SonyLIV JWT token JSON. Returns dict with access_token, contact_id, device_id, etc."""
    try:
        return json.loads(Path(path).read_text())
    except Exception as ex:
        raise ValueError(f"Failed to read token file: {ex}")

def get_device_id(token_data: dict) -> str:
    """Get or generate a device ID from token data."""
    did = token_data.get("device_id", "")
    if not did:
        # Generate a stable UUID from cp_customer_id or random
        seed = token_data.get("cp_customer_id") or token_data.get("mobile") or ""
        if seed:
            did = str(uuid.UUID(hashlib.md5(seed.encode()).hexdigest()))
        else:
            did = str(uuid.uuid4())
    return did

def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verifying signature."""
    try:
        import base64
        parts = token.split(".")
        if len(parts) < 2: return {}
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}

def get_contact_id(token_data: dict) -> str:
    """Extract contactId from token JSON data."""
    cid = (token_data.get("contact_id") or token_data.get("contactId") or
           token_data.get("cp_customer_id") or "")
    if cid and str(cid) != "0":
        return str(cid)
    at = token_data.get("access_token", "")
    if at:
        payload = decode_jwt_payload(at)
        cid = (payload.get("contactID") or payload.get("contactId") or "")
        if cid:
            return str(cid)
    return "0"

def fetch_contact_id_from_api(device_id: str, session_id: str, cookies: dict,
                              log_cb=None) -> str:
    """
    Call GETPROFILE to get the contactId.
    Tries multiple cluster codes since TG may not be this user's cluster.
    Returns contactId string or '0'.
    """
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    headers = {
        "accept":        "application/json, text/plain, */*",
        "app_version":   "3.6.83",
        "device_id":     device_id,
        "origin":        "https://www.sonyliv.com",
        "referer":       "https://www.sonyliv.com/",
        "session_id":    session_id,
        "user-agent":    UA,
        "x-via-device":  "true",
        "cookie":        cookie_str,
    }

    _at = _get_access_token()
    if _at:
        headers["authorization"] = f"Bearer {_at}"

    # Try common clusters - GETPROFILE also needs a valid cluster
    for cluster in ["AP", "TG", "KL", "MH", "TN", "KA", "DL", "GJ", "UP"]:
        api = (f"https://apiv2.sonyliv.com/AGL/2.9/A/ENG/WEB/IN/{cluster}"
               f"/GETPROFILE?channelPartnerID=MSMIND")
        try:
            try:
                import requests as req_lib
                r = req_lib.get(api, headers=headers, timeout=10)
                data = r.json()
            except ImportError:
                req = urllib.request.Request(api, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as r:
                    data = json.loads(r.read())

            if log_cb:
                log_cb(f"[GETPROFILE/{cluster}] resultCode={data.get('resultCode')} "
                       f"keys={list(data.get('resultObj',{}).keys())[:8]}")

            msg = data.get("message","") or data.get("errorDescription","")
            if "cluster" in msg.lower():
                continue

            result = data.get("resultObj", {})
            # contactId can be nested in profile or at top level
            cid = (result.get("contactId") or result.get("contactID") or
                   result.get("userId")    or result.get("userID")    or
                   result.get("id")        or "")
            if not cid:
                profile = result.get("profile", result.get("userProfile", {}))
                cid = (profile.get("contactId") or profile.get("contactID") or
                       profile.get("userId") or "")
            if cid and str(cid) != "0":
                return str(cid)
        except Exception as ex:
            if log_cb:
                log_cb(f"[GETPROFILE/{cluster}] exception: {ex}")
            continue

    return "0"

def fetch_video_url(content_id: str, contact_id: str, device_id: str,
                    cookies: dict, cluster: str = "KL") -> dict:
    """
    POST /AGL/5.0/SR/ENG/WEB/IN/{cluster}/CONTENT/VIDEOURL/VOD/{contentId}
    'SR' at position-3 is FIXED (). The {cluster} at position-7
    is the region code (KL=Kerala, TN=TamilNadu, MH=Maharashtra, etc.)
    and must match the user's registered region - we try them all.
    Returns the full API response dict.
    """
    contact_param = f"?contactId={contact_id}" if contact_id and contact_id != "0" else ""
    api = (f"https://apiv2.sonyliv.com/AGL/5.0/SR/ENG/WEB/IN/{cluster}"
           f"/CONTENT/VIDEOURL/VOD/{content_id}{contact_param}")

    import hashlib, uuid as _uuid
    # ppid = sl_ppid cookie (32-char hex, no timestamp) - : 79e98604d8752b4dec90bb9793c9cff2
    ppid       = cookies.get("sl_ppid", hashlib.md5(device_id.encode()).hexdigest())
    # session_id = 32-char_md5 + dash + timestamp_ms (different from device_id) - 
    session_id = hashlib.md5(str(_uuid.uuid4()).encode()).hexdigest() + f"-{int(time.time()*1000)}"
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    payload = json.dumps({
        "actionType":      "play",
        "browser":         "Chrome",
        "deviceId":        device_id,
        "os":              "Windows",
        "platform":        "web",
        "hasLAURLEnabled": True,
        "adsParams": {
            "Idtype":  "uuid",
            "Is_lat":  "0",
            "ppid":    ppid,
            "preroll": "disable"
        }
    }).encode()

    td_hints = json.dumps({
        "os_name":          "Windows",
        "os_version":       "10",
        "device_make":      "none",
        "device_model":     "none",
        "display_res":      "1920",
        "viewport_res":     "868",
        "conn_type":        "4g",
        "supp_codec":       "H264,AV1,AAC",
        "client_throughput":"16000",
        "td_user_agent":    UA,
        "hdr_decoder":      "UNKNOWN",
        "audio_decoder":    "STEREO",
        "app_version":      "3.6.83"
    })

    access_token = _get_access_token()
    headers = {
        "accept":             "application/json, text/plain, */*",
        "accept-language":    "en-GB,en-IN;q=0.9,en-US;q=0.8,en;q=0.7",
        "advertiserid":       device_id,
        "app_version":        "3.6.83",
        "content-type":       "application/json",
        "device_id":          device_id,
        "origin":             "https://www.sonyliv.com",
        "referer":            "https://www.sonyliv.com/",
        "sec-ch-ua":          '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
        "sec-ch-ua-mobile":   "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest":     "empty",
        "sec-fetch-mode":     "cors",
        "sec-fetch-site":     "same-site",
        "session_id":         session_id,
        "td_client_hints":    td_hints,
        "user-agent":         UA,
        "x-via-device":       "true",
        "cookie":             cookie_str,
    }
    # Bearer token - this is what proves subscription to the API
    if access_token:
        headers["authorization"] = f"Bearer {access_token}"

    try:
        import requests as req_lib
        resp = req_lib.post(api, data=payload, headers=headers, timeout=20,
                            verify=True)
        return resp.json()
    except ImportError:
        pass
    except Exception:
        pass  # fall through to urllib

    req = urllib.request.Request(api, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())

def parse_stream_info(api_resp: dict) -> dict:
    """
    Extract MPD URL, license URL, KID, content title from SonyLIV VIDEOURL API response.
    confirmed structure:
    {
      "resultObj": {
        "title": "...",
        "episodeTitle": "...",
        "isEncrypted": true,
        "drm_video_kid": "df08ec6a52ea420c9fd96cb3d5600000",   ← KID directly
        "LA_Details": {
          "laURL": "https://wv-sony.service.expressplay.com/hms/wv/rights/?ExpressPlayToken=..."
        },
        "videoDetails": {
          "videoURL": "https://drm.sonyliv.com/.../...mpd",     ← DRM DASH
          "dashUrl": "...",
          "hlsUrl":  "..."
        }
      }
    }
    """
    result = api_resp.get("resultObj", {})
    vd     = result.get("videoDetails", result)  # videoDetails or fallback to result

    def _pick(*keys):
        for k in keys:
            v = vd.get(k) or result.get(k)
            if v: return v
        return ""

    # Prefer DASH/MPD for DRM; HLS fallback for non-DRM
    mpd = _pick("dashUrl", "mpdUrl", "adaptiveUrl", "videoURL", "hlsUrl", "streamingUrl")

    # --- License URL: HAR shows it lives in resultObj.LA_Details.laURL
    la_details = result.get("LA_Details", {})
    la = la_details.get("laURL", la_details.get("laUrl", ""))
    if not la:
        # fallback: older API versions put it flat in videoDetails
        la  = _pick("licenseUrl", "widevineLicenseUrl", "laUrl", "drmLicenseUrl")
        ep  = _pick("expressPlayToken", "widevineToken", "drmToken")
        if ep and not la:
            la = f"https://wv-sony.service.expressplay.com/hms/wv/rights/?ExpressPlayToken={ep}"

    # --- KID: HAR shows resultObj.drm_video_kid (hex, no dashes)
    kid = result.get("drm_video_kid", "")

    title = (_pick("episodeTitle", "title", "contentName", "showName") or "SonyLIV_Video")

    # Flag DRM: catch all known DRM CDN/gateway domains
    is_drm = (
        "sonydrmvod" in mpd or
        "drm.sonyliv.com" in mpd or
        "drmvod" in mpd or
        result.get("isEncrypted", False) or
        bool(la)
    )

    # --- Subtitles: HAR shows resultObj.subtitle[] array with direct VTT URLs
    # These are unencrypted CDN files - NOT in the MPD. Download separately.
    subs = []
    for s in result.get("subtitle", []):
        url_s = s.get("subtitleUrl", "")
        lang  = s.get("subtitleLanguageName", "")
        name  = s.get("subtitleDisplayName", lang)
        if url_s:
            subs.append({"lang": lang.lower(), "name": name, "url": url_s})

    duration_ms = result.get("content_duration", 0)

    return {
        "mpd":         mpd,
        "license":     la,
        "kid":         kid,
        "title":       title,
        "is_drm":      is_drm,
        "api_subs":    subs,          # [{lang, name, url}] - VTT, unencrypted
        "duration_ms": duration_ms,
        "raw":         api_resp
    }

# --- MPD stream parser (for quality picker)
def parse_mpd_streams(mpd_url: str, cookies: dict, log_cb=None) -> dict:
    """
    Fetch the MPD and return available video + audio streams.
    Returns {
      "video": [{"id":"7-1080v2","res":"1920x1080","kbps":4973,"label":"1080p · 4973 Kbps"}, …],
      "audio": [{"id":"hin-1","lang":"hin","kbps":136,"label":"Hindi · 136 Kbps"}, …]
    }
    """
    import xml.etree.ElementTree as ET

    is_drm_domain = "drm.sonyliv.com" in mpd_url or "sonydrmvod" in mpd_url or "drmvod" in mpd_url
    raw_did = cookies.get("sl_device_token", cookies.get("sl_ppid", ""))

    def _make_session_id():
        h = hashlib.md5(uuid.uuid4().bytes).hexdigest()
        return f"slv{h}{str(int(time.time()*1000))}"

    headers = {"User-Agent": UA, "Referer": "https://www.sonyliv.com/",
                "Origin": "https://www.sonyliv.com", "Accept": "*/*"}
    if is_drm_domain:
        if raw_did: headers["x-did"] = raw_did
        headers["x-playback-session-id"] = _make_session_id()
    else:
        bearer = _get_access_token()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

    try:
        req = urllib.request.Request(mpd_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            mpd_xml = r.read().decode("utf-8", errors="replace")
    except Exception as ex:
        if log_cb: log_cb(f"[!] MPD stream parse failed: {ex}")
        return {"video": [], "audio": [], "subs": []}

    video_streams = []
    audio_streams = []
    sub_streams   = []

    try:
        root = ET.fromstring(mpd_xml)
        def _strip_ns(tag):
            return tag.split("}")[-1] if "}" in tag else tag

        _seen_video = set(); _seen_audio = set(); _seen_sub = set()

        for adapt in root.iter():
            if _strip_ns(adapt.tag) != "AdaptationSet":
                continue
            mime    = adapt.get("mimeType","") or adapt.get("contentType","")
            lang    = adapt.get("lang","") or ""
            role    = ""
            for child in adapt:
                if _strip_ns(child.tag) == "Role":
                    role = child.get("value","")

            for rep in adapt:
                if _strip_ns(rep.tag) != "Representation":
                    continue
                rid    = rep.get("id","")
                bw     = int(rep.get("bandwidth", 0)) // 1000
                width  = rep.get("width","")
                height = rep.get("height","")

                if "text" in mime or "ttml" in mime or "vtt" in mime or "application/mp4" in mime and lang:
                    # subtitle / caption track
                    if rid in _seen_sub: continue
                    _seen_sub.add(rid)
                    lang_str = lang or "und"
                    label    = f"{lang_str.upper()} subtitle"
                    sub_streams.append({"id": rid, "lang": lang_str,
                                        "label": label, "code": lang_str})
                elif "video" in mime or (width and "audio" not in mime):
                    if rid in _seen_video: continue
                    _seen_video.add(rid)
                    try:    h = int(height); w = int(width)
                    except: h = 0; w = 0
                    res   = f"{w}x{h}" if w and h else "?"
                    mbps  = bw / 1000
                    label = f"{h}p · {bw} Kbps  [{rid}]"
                    video_streams.append({"id": rid, "res": res,
                                          "height": h, "width": w,
                                          "kbps": bw, "mbps": mbps,
                                          "label": label})
                elif "audio" in mime:
                    if rid in _seen_audio: continue
                    _seen_audio.add(rid)
                    lang_str = lang or rep.get("lang","") or "und"
                    label    = f"{lang_str.upper()} · {bw} Kbps  [{rid}]"
                    audio_streams.append({"id": rid, "lang": lang_str,
                                          "kbps": bw, "label": label,
                                          "code": lang_str})

        video_streams.sort(key=lambda x: -x["kbps"])
        audio_streams.sort(key=lambda x: -x["kbps"])
        # dedupe subs by lang
        seen_sl = set()
        sub_streams = [s for s in sub_streams
                       if not (s["lang"] in seen_sl or seen_sl.add(s["lang"]))]
    except Exception as ex:
        if log_cb: log_cb(f"[!] MPD parse error: {ex}")

    return {"video": video_streams, "audio": audio_streams, "subs": sub_streams}

# --- downloader engines
def run_n_m3u8dl(mpd, license_url, title, out_dir, cfg, log_cb, cookies=None, kid=None,
                 video_id=None, audio_id=None, audio_langs=None, sub_langs=None,
                 api_subs=None):
    """
    audio_langs: list of lang codes e.g. ["tel","tam"] → lang=(tel|tam):for=best2
    sub_langs:   list of lang codes or None/[] → no subs, ["all"] → all subs
    api_subs:    [{lang, name, url}] - VTT files from VIDEOURL API (unencrypted CDN)
    audio_id:    single stream ID (legacy, lower priority)
    """
    exe = cfg.get("n_m3u8dl_exe", "N_m3u8DL-RE")
    safe_title = re.sub(r'[\\/:*?"<>|]', '_', title)
    out_path   = os.path.join(out_dir, f"{safe_title}.mkv")

    cmd = [
        exe, mpd,
        "--save-dir",  out_dir,
        "--save-name", safe_title,
        "--binary-merge",
        "--concurrent-download",   # download video + audio tracks in parallel
    ]

    # --- Video stream selection
    if video_id and video_id not in ("best", "auto", ""):
        cmd += ["--select-video", f"id={video_id}"]
    else:
        cmd += ["--select-video", "best"]

    # --- Audio stream selection
    # Prefer audio_langs list (multi-track checkbox selection)
    if audio_langs and len(audio_langs) > 0:
        codes = [c.strip().lower() for c in audio_langs if c.strip()]
        if len(codes) == 1:
            cmd += ["--select-audio", f"lang={codes[0]}:for=best"]
        else:
            lang_re = "|".join(codes)
            n = len(codes)
            cmd += ["--select-audio", f"lang=({lang_re}):for=best{n}"]
    elif audio_id and audio_id not in ("best", "auto", ""):
        cmd += ["--select-audio", f"id={audio_id}"]
    else:
        cmd += ["--select-audio", "best"]

    # --- Subtitle stream selection
    if sub_langs:
        codes_s = [c.strip().lower() for c in sub_langs if c.strip()]
        if "all" in codes_s:
            cmd += ["--select-subtitle", "all"]
        elif len(codes_s) == 1:
            cmd += ["--select-subtitle", f"lang={codes_s[0]}"]
        elif len(codes_s) > 1:
            sub_re = "|".join(codes_s)
            cmd += ["--select-subtitle", f"lang=({sub_re})"]

    # --- confirmed header strategy
    # drm.sonyliv.com (DRM DASH gateway): needs x-did + x-playback-session-id.
    #   NO cookies, NO Authorization Bearer - Akamai bot detection kills those → 403.
    # Non-DRM Sony CDN: Bearer auth optional; no DRM headers needed.
    is_drm_domain = ("drm.sonyliv.com" in mpd or "sonydrmvod" in mpd or "drmvod" in mpd)

    def _make_session_id():
        h = hashlib.md5(uuid.uuid4().bytes).hexdigest()
        return f"slv{h}{str(int(time.time() * 1000))}"

    raw_did = (cookies or {}).get("sl_device_token", (cookies or {}).get("sl_ppid", ""))

    cmd += ["--header", f"User-Agent:{UA}"]
    cmd += ["--header", "Referer:https://www.sonyliv.com/"]
    cmd += ["--header", "Origin:https://www.sonyliv.com"]

    if is_drm_domain:
        if raw_did:
            cmd += ["--header", f"x-did:{raw_did}"]
        cmd += ["--header", f"x-playback-session-id:{_make_session_id()}"]
    else:
        bearer = _get_access_token()
        if bearer:
            cmd += ["--header", f"Authorization:Bearer {bearer}"]

    # --- DRM: try Widevine key extraction
    is_drm = ("sonydrmvod" in mpd or "drm.sonyliv.com" in mpd or
              "drmvod" in mpd or bool(license_url))
    if is_drm:
        key_str = fetch_widevine_key(mpd, license_url, cfg, log_cb, cookies=cookies, known_kid=kid)
        if key_str:
            pairs = re.findall(r'([0-9a-fA-F]{32}:[0-9a-fA-F]{32})', key_str)
            if not pairs:
                bare = key_str.replace("--key", "").strip()
                if ":" in bare:
                    pairs = [bare]
            for pair in pairs:
                cmd += ["--key", pair]
            mp4d = cfg.get("mp4decrypt_exe", "mp4decrypt")
            cmd += ["--decryption-binary-path", mp4d]
            # ← NO --mux-after-done here; we mux with mkvmerge ourselves below
        else:
            log_cb("[!] No Widevine key obtained - DRM content will likely fail")
            log_cb("[!] Make sure WVD Device File is set in Settings and pywidevine is installed")

    # --- Speed: bump thread count from default 16 → 32
    thread_count = str(cfg.get("thread_count", 32))
    cmd += ["--thread-count", thread_count]
    cmd += ["--log-level", "INFO"]
    log_cb(f"[CMD] {' '.join(cmd)}\n")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace"
    )

    # --- Parse N_m3u8DL-RE progress lines for live ETA display
    # Format: "Vid 426x240 | 293 Kbps   ----  7/2204 0.32%   1.59KB/3.42MB  1.59KBps  00:03:18"
    import re as _re
    _eta_pat  = _re.compile(r'(\d+)/(\d+)\s+([\d.]+)%.*?(\d+\.\d+[KMG]?B(?:ps)?)\s+(\d{2}:\d{2}:\d{2})')
    _dur_pat  = _re.compile(r'~(\d{2}h\d{2}m\d{2}s)')
    _last_eta = {}   # track_label → eta string

    for line in proc.stdout:
        line = line.rstrip()
        log_cb(line)
        dm = _dur_pat.search(line)
        if dm and "duration_str" not in (cfg.get("_parsed") or {}):
            pass  # already logged from API above
        # Extract ETA per-track and surface the worst (slowest) one
        em = _eta_pat.search(line)
        if em:
            done, total, pct, speed, eta = em.groups()
            # grab track label (first word before the progress bar)
            label = line.split()[0]
            _last_eta[label] = (float(pct), eta, speed)
            if _last_eta:
                # Pick the track with lowest % = slowest = limiting ETA
                slowest = min(_last_eta.values(), key=lambda x: x[0])
                log_cb(f"[ETA] {slowest[2]} - {slowest[1]} remaining ({slowest[0]:.1f}%)")

    proc.wait()
    ok = proc.returncode == 0

    if not ok:
        return False, out_path

    # --- Download API-sourced subtitles (VTT from SonyLIV CDN - not in MPD)
    import glob as _glob
    import urllib.request as _urlreq

    downloaded_subs = []
    for sub_info in (api_subs or []):
        lang = sub_info.get("lang", "und")
        url_s = sub_info.get("url", "")
        if not url_s:
            continue
        ext     = os.path.splitext(url_s)[-1] or ".vtt"
        sub_out = os.path.join(out_dir, f"{safe_title}.{lang}{ext}")
        try:
            log_cb(f"[...] Downloading subtitle [{lang}] → {os.path.basename(sub_out)}")
            req = _urlreq.Request(url_s, headers={"User-Agent": UA,
                                                   "Referer": "https://www.sonyliv.com/"})
            with _urlreq.urlopen(req, timeout=20) as r, open(sub_out, "wb") as fout:
                fout.write(r.read())
            downloaded_subs.append(sub_out)
            log_cb(f"[✓] Subtitle downloaded: {os.path.basename(sub_out)}")
        except Exception as sub_ex:
            log_cb(f"[!] Subtitle download failed [{lang}]: {sub_ex}")

    # --- mkvmerge: merge all decrypted tracks into one MKV
    # N_m3u8DL-RE actual output naming (after mp4decrypt):
    #   video  → {safe_title}          (NO extension)
    #   audio  → {safe_title}.kan / .tel / .hin / .eng etc.
    #   mp4decrypt temps → {safe_title}_dec  OR  {hash}_dec
    #   subs   → {safe_title}.srt / .ass / .vtt  (if any)
    mkv_out     = os.path.join(out_dir, f"{safe_title}.mkv")
    sub_exts    = {".srt", ".ass", ".vtt"}
    skip_exts   = {".mkv", ".mpd", ".m3u8", ".tmp", ".json"}

    all_candidates = _glob.glob(os.path.join(out_dir, f"{safe_title}*"))

    track_files = []
    sub_files   = []
    for f in sorted(all_candidates):
        if not os.path.isfile(f):
            continue
        if f == mkv_out:          # never include the output we're about to write
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext in skip_exts:
            continue
        if ext in sub_exts:
            sub_files.append(f)
        else:
            track_files.append(f)   # video (no ext) OR audio (.kan/.tel/…)

    # Add API-downloaded subs that aren't already picked up from glob
    for ds in downloaded_subs:
        if ds not in sub_files and os.path.exists(ds):
            sub_files.append(ds)

    log_cb(f"[i] Tracks found for mux: {[os.path.basename(x) for x in track_files]}")
    log_cb(f"[i] Subs found for mux:   {[os.path.basename(x) for x in sub_files]}")

    if track_files:
        mkvmerge_exe = cfg.get("mkvmerge_exe", "mkvmerge")
        mkv_cmd = [mkvmerge_exe, "-o", mkv_out] + track_files + sub_files
        log_cb(f"[CMD] {' '.join(mkv_cmd)}")
        mkv_proc = subprocess.Popen(
            mkv_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )
        for line in mkv_proc.stdout:
            log_cb(line.rstrip())
        mkv_proc.wait()
        if mkv_proc.returncode in (0, 1):   # mkvmerge 1 = warnings only, still ok
            log_cb(f"[✓] mkvmerge done → {os.path.basename(mkv_out)}")
            out_path = mkv_out
            # --- Nuke ALL temp/source files left behind
            # 1. Track + sub files we just muxed
            for f in track_files + sub_files:
                try: os.remove(f); log_cb(f"[del] {os.path.basename(f)}")
                except Exception as e: log_cb(f"[warn] del {f}: {e}")
            # 2. Any *_dec files mp4decrypt left (hash-named or title-named)
            for dec_f in _glob.glob(os.path.join(out_dir, "*_dec")):
                try: os.remove(dec_f); log_cb(f"[del] {os.path.basename(dec_f)}")
                except Exception as e: log_cb(f"[warn] del {dec_f}: {e}")
            # 3. Any .tmp / .json / key files with safe_title prefix
            for ext_pat in ("*.tmp", "*.json", "*.key"):
                for junk in _glob.glob(os.path.join(out_dir, f"{safe_title}{ext_pat}")):
                    try: os.remove(junk); log_cb(f"[del] {os.path.basename(junk)}")
                    except Exception: pass
        else:
            log_cb(f"[✗] mkvmerge failed (exit {mkv_proc.returncode})")
            ok = False
    else:
        log_cb("[!] No output tracks found to mux - check N_m3u8DL-RE output above")
        ok = False

    return ok, out_path

def run_ytdlp(url, out_dir, cfg, log_cb, access_token=""):
    safe_tmpl = os.path.join(out_dir, "%(title)s.%(ext)s")
    cmd = [
        cfg["ytdlp_exe"],
        "-f",                     "bestvideo+bestaudio/best",
        "--merge-output-format",  "mp4",
        "-o",                     safe_tmpl,
        "--add-header",           f"User-Agent:{UA}",
        "--add-header",           "Referer:https://www.sonyliv.com/",
    ]
    # Pass Bearer token - JWT auth, no cookies needed
    if access_token:
        cmd += ["--add-header", f"Authorization:Bearer {access_token}"]
        cmd += ["--username", "token", "--password", access_token]
        log_cb("[✓] Using JWT Bearer auth for yt-dlp")
    else:
        log_cb("[!] No access token - yt-dlp may prompt for login")
    cmd.append(url)
    log_cb(f"[CMD] {' '.join(cmd)}\n")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace"
    )
    for line in proc.stdout:
        log_cb(line.rstrip())
    proc.wait()
    return proc.returncode == 0

def fetch_widevine_key(mpd_url, license_url, cfg, log_cb, cookies=None, known_kid=None) -> str:
    """
    Use pywidevine + device.wvd to get content key.
    known_kid: hex KID from VIDEOURL API (drm_video_kid field) - used if MPD has no PSSH.
    Returns '--key kid:key --key kid2:key2' string or ''.
    """
    import xml.etree.ElementTree as ET

    wvd = cfg.get("wvd_file","")
    if not wvd or not os.path.exists(wvd):
        log_cb("[!] No device.wvd found - skipping Widevine key fetch")
        log_cb("[!] Set WVD Device File in Settings tab to enable DRM decryption")
        return ""
    try:
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH

        cookie_str = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())

        log_cb("[...] Fetching MPD to extract PSSH + license URL …")

        # --- confirmed: drm.sonyliv.com returns 200 with x-did + x-playback-session-id.
        # NO cookies, NO Authorization Bearer - Akamai bot detection fires if you send them.
        # x-did      = the device-token id from cookies (the part before the first dash)
        # x-playback-session-id = "slv" + md5(random uuid) + unix_ms_timestamp
        is_drm_domain = "drm.sonyliv.com" in mpd_url or "sonydrmvod" in mpd_url or "drmvod" in mpd_url

        def _make_session_id():
            h = hashlib.md5(uuid.uuid4().bytes).hexdigest()
            ts = str(int(time.time() * 1000))
            return f"slv{h}{ts}"

        # device id: prefer sl_device_token full value or sl_ppid
        raw_did = (cookies or {}).get("sl_device_token", (cookies or {}).get("sl_ppid", ""))
        device_id = raw_did  # send as-is; HAR shows full value e.g. "e3d0369a...-1779996755428"

        mpd_headers = {
            "User-Agent": UA,
            "Referer":    "https://www.sonyliv.com/",
            "Origin":     "https://www.sonyliv.com",
            "Accept":     "*/*",
        }

        if is_drm_domain:
            if device_id:
                mpd_headers["x-did"] = device_id
            mpd_headers["x-playback-session-id"] = _make_session_id()
        else:
            bearer = _get_access_token()
            if bearer:
                mpd_headers["Authorization"] = f"Bearer {bearer}"

        req = urllib.request.Request(mpd_url, headers=mpd_headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            mpd_xml = r.read().decode("utf-8", errors="replace")

        log_cb(f"[...] MPD fetched ({len(mpd_xml)} bytes)")

        # --- Parse ContentProtection elements
        pssh_b64   = ""
        la_url_mpd = ""
        tree = ET.fromstring(mpd_xml)

        for elem in tree.iter():
            tag = elem.tag.lower()
            if "contentprotection" not in tag:
                continue
            scheme = elem.get("schemeIdUri","").lower()

            # Widevine UUID = edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
            if "edef8ba9" in scheme:
                for child in elem:
                    ctag = child.tag.lower()
                    if "pssh" in ctag and child.text:
                        pssh_b64 = child.text.strip()
                    # LA URL variants: ms:laurl, dashif:laurl, laurl
                    if any(x in ctag for x in ["laurl","la_url"]):
                        la_url_mpd = child.text.strip() if child.text else elem.get("laUrl","")
                # Also check attributes
                if not la_url_mpd:
                    la_url_mpd = elem.get("laUrl", elem.get("la_url",""))

            # PlayReady sometimes carries the Widevine LA URL too
            if not la_url_mpd and "9a04f079" in scheme:
                for child in elem:
                    if "laurl" in child.tag.lower() and child.text:
                        la_url_mpd = child.text.strip()

        lic_url = (license_url or la_url_mpd or
                   "https://wv-sony.service.expressplay.com/hms/wv/rights/")
        log_cb(f"[→] PSSH found: {'yes' if pssh_b64 else 'NO'}")
        if known_kid:
            log_cb(f"[→] Known KID from API: {known_kid}")
        log_cb(f"[→] License URL: {lic_url[:80]}{'…' if len(lic_url)>80 else ''}")

        if not pssh_b64:
            # Try to build a synthetic PSSH from the known KID (HAR: drm_video_kid field)
            if known_kid:
                log_cb(f"[...] No PSSH in MPD - building synthetic PSSH from KID {known_kid}")
                import base64, struct
                # Widevine PSSH v0: 4 bytes version/flags, 16 bytes WV system id, 4 bytes data len, WV proto payload
                # Minimal WV proto: field 2 (content_id) = KID bytes
                try:
                    kid_bytes = bytes.fromhex(known_kid)
                    # WV PSSH box data: protobuf field 2 (bytes) = KID
                    # field 2, wire type 2 (length-delimited) = 0x12, then varint length, then bytes
                    proto = b'\x12' + bytes([len(kid_bytes)]) + kid_bytes
                    wv_sys_id = bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed")
                    # Full PSSH box: size(4) + "pssh"(4) + version/flags(4) + sysid(16) + datalen(4) + data
                    data_len = struct.pack(">I", len(proto))
                    box_body = b'\x00\x00\x00\x00' + wv_sys_id + data_len + proto
                    box_size = struct.pack(">I", 8 + len(box_body))
                    pssh_box = box_size + b'pssh' + box_body
                    pssh_b64 = base64.b64encode(pssh_box).decode()
                    log_cb(f"[✓] Synthetic PSSH built: {pssh_b64[:60]}…")
                except Exception as e:
                    log_cb(f"[!] Failed to build synthetic PSSH: {e}")
                    return ""
            else:
                log_cb("[!] No Widevine PSSH in MPD and no KID available - can't fetch key")
                return ""

        # --- Widevine CDM flow
        log_cb("[...] Opening Widevine CDM session …")
        device  = Device.load(wvd)
        cdm     = Cdm.from_device(device)
        session = cdm.open()
        pssh    = PSSH(pssh_b64)
        challenge = cdm.get_license_challenge(session, pssh)

        log_cb("[...] Sending license challenge …")
        lic_headers = {
            "User-Agent":   UA,
            "Content-Type": "application/octet-stream",
            "Referer":      "https://www.sonyliv.com/",
        }
        _tok = _get_access_token()
        if _tok:
            lic_headers["Authorization"] = f"Bearer {_tok}"

        lic_req = urllib.request.Request(
            lic_url, data=challenge, headers=lic_headers, method="POST"
        )
        with urllib.request.urlopen(lic_req, timeout=15) as r:
            lic_resp = r.read()

        cdm.parse_license(session, lic_resp)
        keys = [f"{k.kid.hex}:{k.key.hex()}"
                for k in cdm.get_keys(session) if k.type == "CONTENT"]
        cdm.close(session)

        if keys:
            log_cb(f"[✓] Content key(s): {', '.join(keys)}")
            return " --key ".join([""] + keys).strip()  # "--key kid:key --key kid2:key2"
        log_cb("[!] No CONTENT keys returned from CDM")
        return ""

    except ImportError:
        log_cb("[!] pywidevine not installed - run: pip install pywidevine")
        return ""
    except Exception as ex:
        log_cb(f"[!] Widevine key fetch error: {ex}")
        return ""

# --- CheckRow widget (Hotstar style)
class CheckRow(tk.Frame):
    """Canvas-drawn checkbox row - exact Hotstar style with hover BG.

    New flexible signature:
      CheckRow(parent, var, q_label, res_label=..., bit_label=..., size_label=...,
               color=..., is_top=False)
    Legacy positional also accepted:
      CheckRow(parent, var, height_p, width_p, mbps, est_size, is_top=False)
    """
    def __init__(self, parent, var, q_label,
                 # new-style kwargs
                 res_label=None, bit_label=None, size_label=None,
                 color=None, is_top=False,
                 # legacy positional (width_p, mbps, est_size)
                 *args, **kw):
        # strip our known kwargs so they don't pollute Frame()
        super().__init__(parent, bg=BG2, cursor="hand2")
        self.var = var
        self._hovered = False

        # Handle legacy positional: (height_p, width_p, mbps, est_size)
        # when called as CheckRow(parent, var, height_p, width_p, mbps, est_size)
        # args = (width_p, mbps, est_size)
        if args:
            width_p = args[0] if len(args) > 0 else 0
            mbps    = args[1] if len(args) > 1 else 0
            est_sz  = args[2] if len(args) > 2 else "-"
            height_p = q_label  # q_label is actually height int in legacy mode
            q_color = {1080: ACC3, 720: GRN, 480: YLW, 360: ORG}.get(height_p, FG2)
            _ql  = f"{height_p}p"
            _rl  = f"{width_p}×{height_p}"
            _bl  = f"{mbps:.1f} Mbps"
            _sl  = est_sz
            _col = q_color
        else:
            _ql  = str(q_label)
            _rl  = res_label  or "-"
            _bl  = bit_label  or "-"
            _sl  = size_label or "-"
            _col = color      or FG2

        self.cv = tk.Canvas(self, width=18, height=18, bg=BG2,
                             highlightthickness=0, cursor="hand2")
        self.cv.pack(side="left", padx=(6, 8), pady=6)
        self._draw()

        tk.Label(self, text=_ql, bg=BG2, fg=_col,
                 font=("Consolas", 10, "bold"), width=6, anchor="w").pack(side="left")
        tk.Label(self, text=_rl, bg=BG2, fg=FG2,
                 font=("Consolas", 9), width=11, anchor="w").pack(side="left")
        tk.Label(self, text=_bl, bg=BG2, fg=FG2,
                 font=("Consolas", 9), width=10, anchor="w").pack(side="left")
        tk.Label(self, text=_sl, bg=BG2,
                 fg=GRN if is_top else FG2,
                 font=("Consolas", 9, "bold" if is_top else "normal"),
                 width=10, anchor="w").pack(side="left")

        self._bind_all(self)
        self.var.trace_add("write", lambda *a: self._draw())

    def _bind_all(self, w):
        w.bind("<Button-1>", self._toggle)
        w.bind("<Enter>",    self._on_enter)
        w.bind("<Leave>",    self._on_leave)
        for child in w.winfo_children():
            self._bind_all(child)

    def _toggle(self, e=None): self.var.set(not self.var.get())
    def _on_enter(self, e=None): self._hovered = True;  self._set_bg(BG4)
    def _on_leave(self, e=None): self._hovered = False; self._set_bg(BG2)

    def _set_bg(self, c):
        self.configure(bg=c); self.cv.configure(bg=c)
        for w in self.winfo_children():
            try: w.configure(bg=c)
            except: pass

    def _draw(self):
        cv = self.cv; cv.delete("all")
        checked = self.var.get()
        fill    = ACC if checked else BG3
        outline = ACC if checked else FG3
        cv.create_rectangle(1, 1, 17, 17, fill=fill, outline=outline, width=1)
        if checked:
            cv.create_line(3, 9,  7, 13, fill="#fff", width=2, capstyle="round")
            cv.create_line(7, 13, 15, 5, fill="#fff", width=2, capstyle="round")


# --- GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.cfg = load_cfg()
        self.title("SonyLIV Downloader  •  Cookie Edition")
        self.geometry("900x640")
        self.resizable(True, True)
        self.configure(bg=BG)
        self._session = {}
        self._build_styles()
        self._build_ui()
        self._reload_session()

    # --- TTK STYLES (Hotstar palette)
    def _build_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, font=FONT)
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("TButton", background=ACC, foreground="#fff",
                    font=FONTB, borderwidth=0, padding=(14, 7), relief="flat")
        s.map("TButton",
              background=[("active", ACC2), ("disabled", BG3)],
              foreground=[("disabled", FG2)])
        s.configure("Ghost.TButton", background=BG3, foreground=FG2,
                    font=("Segoe UI", 9), padding=(10, 5), relief="flat", borderwidth=0)
        s.map("Ghost.TButton",
              background=[("active", ACC), ("disabled", BG3)],
              foreground=[("active", "#fff"), ("disabled", FG3)])
        s.configure("Cancel.TButton", background="#7f1d1d", foreground=RED,
                    font=FONTB, padding=(14, 7), relief="flat", borderwidth=0)
        s.map("Cancel.TButton", background=[("active", "#991b1b")])
        s.configure("DRM.TButton", background="#1a1a2e", foreground=YLW,
                    font=("Segoe UI", 9), padding=(10, 5), relief="flat", borderwidth=0)
        s.map("DRM.TButton", background=[("active", "#2a2a4e")])
        s.configure("TEntry", fieldbackground=BG3, foreground=FG,
                    insertcolor=ACC3, borderwidth=0, relief="flat", padding=6)
        s.configure("Prog.Horizontal.TProgressbar",
                    troughcolor=BG3, background=ACC, borderwidth=0, thickness=8,
                    lightcolor=ACC, darkcolor=ACC2)

    # --- top bar
    def _build_ui(self):
        top = tk.Frame(self, bg=BG2, height=52)
        top.pack(fill="x")
        top.pack_propagate(False)

        tk.Label(top, text="▶", font=("Segoe UI", 18), bg=BG2, fg=ACC).pack(side="left", padx=(14,4), pady=8)
        tk.Label(top, text="SonyLIV Downloader", font=("Segoe UI", 14, "bold"), bg=BG2, fg=FG).pack(side="left", pady=8)

        self._status_dot = tk.Label(top, text="●", font=("Segoe UI",12), bg=BG2, fg=RED)
        self._status_dot.pack(side="right", padx=(0,8))
        self._status_lbl = tk.Label(top, text="No session", font=FONTL, bg=BG2, fg=FG2)
        self._status_lbl.pack(side="right", padx=(0,4))

        tab_bar = tk.Frame(self, bg=BG2)
        tab_bar.pack(fill="x")
        self._tabs = {}
        self._active_tab = tk.StringVar(value="login")
        for name, label in [("login","Login"), ("download","Download"), ("settings","Settings")]:
            btn = tk.Button(tab_bar, text=label, font=FONTB, bg=BG2, fg=FG2,
                            relief="flat", bd=0, padx=20, pady=8, cursor="hand2",
                            activebackground=BG3, activeforeground=FG,
                            command=lambda n=name: self._switch_tab(n))
            btn.pack(side="left")
            self._tabs[name] = btn

        self._frames = {}
        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True)

        for name, builder in [
            ("login",    self._build_login),
            ("download", self._build_download),
            ("settings", self._build_settings),
        ]:
            f = tk.Frame(container, bg=BG)
            builder(f)
            f.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._frames[name] = f

        self._switch_tab("login")

    def _switch_tab(self, name):
        self._active_tab.set(name)
        for n, btn in self._tabs.items():
            if n == name:
                btn.configure(bg=ACC, fg="white")
            else:
                btn.configure(bg=BG2, fg=FG2)
        for n, f in self._frames.items():
            f.lift() if n == name else f.lower()

    # --- LOGIN TAB
    def _build_login(self, parent):
        self._pw_cancel = [False]
        self._pw_result = [None]

        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        sb     = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        _win  = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(_win, width=e.width))

        tk.Label(inner, text="", bg=BG).pack(pady=8)

        # --- SECTION 1: Phone OTP Login via browser
        otp_card = tk.Frame(inner, bg=BG2); otp_card.pack(padx=40, fill="x", pady=(0,10))

        hdr = tk.Frame(otp_card, bg=BG2); hdr.pack(fill="x", padx=30, pady=(14,0))
        tk.Label(hdr, text="📱  Phone OTP Login", font=("Segoe UI", 12, "bold"),
                 bg=BG2, fg=ACC3).pack(side="left")
        self._otp_status_lbl = tk.Label(hdr, text="", font=FONTL, bg=BG2, fg=FG2)
        self._otp_status_lbl.pack(side="right")

        tk.Frame(otp_card, bg=BG3, height=1).pack(fill="x", padx=30, pady=(8,12))

        tk.Label(otp_card,
                 text="Click below → browser opens on SonyLIV → log in yourself → token saves automatically",
                 font=FONTL, bg=BG2, fg=FG2, wraplength=480, justify="left"
                 ).pack(padx=30, anchor="w", pady=(0, 12))

        self._btn_open_login = tk.Button(
            otp_card, text="  🌐  Open SonyLIV & Login  ", font=FONTB,
            bg=ACC, fg="white", relief="flat", pady=11, cursor="hand2",
            activebackground=ACC2, command=self._otp_open_browser)
        self._btn_open_login.pack(fill="x", padx=30, pady=(0, 8))

        self._btn_cancel_login = tk.Button(
            otp_card, text="Cancel", font=FONTL,
            bg=BG3, fg=FG2, relief="flat", pady=6, cursor="hand2",
            command=self._otp_cancel, state="disabled")
        self._btn_cancel_login.pack(fill="x", padx=30, pady=(0, 14))

        # --- SECTION 2: Load from token file (secondary)
        tk.Label(inner, text="", bg=BG).pack(pady=2)
        file_card = tk.Frame(inner, bg=BG2); file_card.pack(padx=40, fill="x", pady=(0,10))

        tk.Label(file_card, text="📂  Load Token File", font=("Segoe UI", 11, "bold"),
                 bg=BG2, fg=FG2).pack(anchor="w", padx=30, pady=(12,4))
        tk.Frame(file_card, bg=BG3, height=1).pack(fill="x", padx=30)

        row1 = tk.Frame(file_card, bg=BG2); row1.pack(fill="x", padx=30, pady=10)
        tk.Label(row1, text="Token  (.json)", font=FONTL, bg=BG2, fg=FG2,
                 width=16, anchor="w").pack(side="left")
        self._cookie_path = tk.StringVar(
            value=self.cfg.get("token_file", str(Path.home() / ".sonyliv_token.json")))
        tk.Entry(row1, textvariable=self._cookie_path, font=FONT, bg=BG3, fg=FG,
                 insertbackground=FG, relief="flat", highlightthickness=1,
                 highlightbackground=BG3, highlightcolor=ACC
                 ).pack(side="left", fill="x", expand=True, ipady=5)
        tk.Button(row1, text="Browse", font=FONTL, bg=BG3, fg=FG2,
                  relief="flat", cursor="hand2", padx=10,
                  command=self._browse_cookies).pack(side="left", padx=(6,0))

        btn_row = tk.Frame(file_card, bg=BG2); btn_row.pack(fill="x", padx=30, pady=(0,12))
        tk.Button(btn_row, text="  Load Session  ", font=FONTB,
                  bg=ACC2, fg="white", relief="flat", padx=16, pady=7,
                  cursor="hand2", activebackground=ACC,
                  command=self._load_session).pack(side="left")

        # --- SECTION 3: Session info
        tk.Label(inner, text="", bg=BG).pack(pady=2)
        sess_card = tk.Frame(inner, bg=BG2); sess_card.pack(padx=40, fill="x", pady=(0,20))

        tk.Label(sess_card, text="Session Info", font=FONTB, bg=BG2, fg=FG2
                 ).pack(anchor="w", padx=30, pady=(12,4))
        tk.Frame(sess_card, bg=BG3, height=1).pack(fill="x", padx=30)

        info = tk.Frame(sess_card, bg=BG2); info.pack(fill="x", padx=30, pady=10)
        self._session_txt = tk.Text(info, height=7, font=FONTL, bg=BG3, fg=FG,
                                    relief="flat", state="disabled", wrap="word",
                                    insertbackground=FG)
        self._session_txt.pack(fill="x")
        btns = tk.Frame(info, bg=BG2); btns.pack(anchor="w", pady=(8,0))
        tk.Button(btns, text="Clear Session", font=FONTL, bg=BG3, fg=FG2,
                  relief="flat", cursor="hand2", padx=8, pady=4,
                  command=self._clear_session).pack(side="left")
        tk.Button(btns, text="Re-login", font=FONTL, bg=BG3, fg=FG2,
                  relief="flat", cursor="hand2", padx=8, pady=4,
                  command=self._otp_new_login).pack(side="left", padx=(8,0))

    # --- OTP login handlers (Playwright manual browser)
    def _otp_set_status(self, msg, color=None):
        self._otp_status_lbl.configure(text=msg, fg=color or FG2)
        self.update_idletasks()

    def _otp_open_browser(self):
        """Launch visible browser → chief logs in → auto-capture token."""
        self._pw_cancel[0] = True          # kill any existing pw thread
        time.sleep(0.1)
        self._pw_cancel = [False]
        self._pw_result = [None]

        self._btn_open_login.configure(text="Browser opening…", state="disabled")
        self._btn_cancel_login.configure(state="normal")
        self._otp_set_status("Waiting for you to log in… (browser is open)", FG2)

        log = self._log if hasattr(self, "_log") else print

        threading.Thread(
            target=_pw_run_manual,
            args=(self._pw_result, log, self._pw_cancel),
            daemon=True
        ).start()
        self.after(500, self._pw_poll_result)

    def _otp_cancel(self):
        self._pw_cancel[0] = True
        self._btn_open_login.configure(text="  🌐  Open SonyLIV & Login  ", state="normal")
        self._btn_cancel_login.configure(state="disabled")
        self._otp_set_status("Cancelled", FG2)

    def _pw_poll_result(self):
        """Poll every 500ms until the PW thread delivers a result."""
        if self._pw_cancel[0]:
            return
        result = self._pw_result[0]
        if result is None:
            self.after(500, self._pw_poll_result)
            return
        self._btn_open_login.configure(text="  🌐  Open SonyLIV & Login  ", state="normal")
        self._btn_cancel_login.configure(state="disabled")
        if result.get("error"):
            err = result["error"]
            if err == "playwright_missing":
                self._otp_set_status("✗ Playwright missing - run: pip install playwright && python -m playwright install chrome", RED)
            else:
                self._otp_set_status(f"✗ {err}", RED)
            return
        td = result.get("token_data", {})
        if td:
            self._otp_finish_login(td)

    def _otp_finish_login(self, td):
        save_path = self.cfg.get("token_file", str(Path.home() / ".sonyliv_token.json"))
        try:
            Path(save_path).write_text(json.dumps(td, indent=2))
        except Exception as ex:
            self._otp_set_status(f"⚠ Save failed: {ex}", YLW)

        device_id  = get_device_id(td)
        contact_id = get_contact_id(td)
        self._session = {"token": td, "device_id": device_id,
                         "contact_id": contact_id, "token_file": save_path,
                         "cookies": {}}
        _set_active_token(td)
        self.cfg["token_file"] = save_path
        save_cfg(self.cfg)

        name = (td.get("first_name","") + " " + td.get("last_name","")).strip() or "-"
        self._otp_set_status(f"✓ Logged in as {name}", GREEN)
        self._update_session_ui(td, device_id, contact_id, save_path)

    def _otp_new_login(self):
        """Reset - ready for a fresh login attempt."""
        self._pw_cancel[0] = True
        self._btn_open_login.configure(text="  🌐  Open SonyLIV & Login  ", state="normal")
        self._btn_cancel_login.configure(state="disabled")
        self._otp_set_status("", FG2)

    # --- File-based session handlers
    def _browse_cookies(self):
        p = filedialog.askopenfilename(filetypes=[("Token JSON","*.json"),("All","*.*")])
        if p: self._cookie_path.set(p)

    def _load_session(self):
        path = self._cookie_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error","Token file not found"); return
        try:
            token_data = load_token(path)
            device_id  = get_device_id(token_data)
            contact_id = get_contact_id(token_data)
            self._session = {"token": token_data, "device_id": device_id,
                             "contact_id": contact_id, "token_file": path,
                             "cookies": {}}
            _set_active_token(token_data)
            self.cfg["token_file"] = path
            save_cfg(self.cfg)
            self._update_session_ui(token_data, device_id, contact_id, path)
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _update_session_ui(self, token_data, device_id, contact_id="", path=""):
        self._status_dot.configure(fg=GREEN)
        self._status_lbl.configure(text="Session loaded")
        cid_str = contact_id if contact_id and contact_id != "0" else "(not found)"
        at  = token_data.get("access_token","")
        exp = token_data.get("expires_at","")
        name = (token_data.get("first_name","") + " " +
                token_data.get("last_name","")).strip() or "unknown"
        sub_str = "✓ Yes" if token_data.get("is_subscribed") else "✗ No"
        mob = token_data.get("mobile","")
        src = "OTP login" if not path else path
        txt = (f"✓ {src}\n"
               f"  Name      : {name}  (+91 {mob})\n"
               f"  Contact ID: {cid_str}\n"
               f"  Device ID : {device_id[:40]}{'…' if len(device_id)>40 else ''}\n"
               f"  Bearer    : {at[:30]}…\n"
               f"  Expires   : {exp}\n"
               f"  Subscribed: {sub_str}")
        self._set_text(self._session_txt, txt)

    def _clear_session(self):
        self._session = {}
        _set_active_token({})
        self._status_dot.configure(fg=RED)
        self._status_lbl.configure(text="No session")
        self._set_text(self._session_txt, "✗ No session - login via OTP or load token file")

    def _reload_session(self):
        path = self.cfg.get("token_file", str(Path.home() / ".sonyliv_token.json"))
        if path and os.path.exists(path):
            try:
                token_data = load_token(path)
                device_id  = get_device_id(token_data)
                contact_id = get_contact_id(token_data)
                self._session = {"token": token_data, "device_id": device_id,
                                 "contact_id": contact_id, "token_file": path,
                                 "cookies": {}}
                _set_active_token(token_data)
                self._update_session_ui(token_data, device_id, contact_id, path)
                return
            except: pass
        self._set_text(self._session_txt, "✗ No session - login via OTP or load token file")

    # --- DOWNLOAD TAB
    def _build_download(self, parent):
        pad = dict(padx=30, pady=8)

        top = tk.Frame(parent, bg=BG2)
        top.pack(fill="x", padx=0, pady=0)

        url_row = tk.Frame(top, bg=BG2); url_row.pack(fill="x", **pad)
        tk.Label(url_row, text="SonyLIV URL or Content ID", font=FONTL,
                 bg=BG2, fg=FG2).pack(anchor="w")
        self._url_var = tk.StringVar()
        url_entry = tk.Entry(url_row, textvariable=self._url_var, font=FONT,
                             bg=BG3, fg=FG, insertbackground=FG, relief="flat",
                             highlightthickness=1, highlightbackground=BG3,
                             highlightcolor=ACC)
        url_entry.pack(fill="x", ipady=7, pady=(4,0))

        btn_row = tk.Frame(top, bg=BG2); btn_row.pack(fill="x", padx=30, pady=4)
        ttk.Button(btn_row, text="🔍 Fetch Info",
                   command=self._fetch_info, style="Ghost.TButton").pack(side="left", padx=(0,8))

        # --- Quality card (Hotstar-style unified panel)
        qc = tk.Frame(parent, bg=BG2); qc.pack(fill="x", padx=14, pady=(0,8))
        qi = tk.Frame(qc, bg=BG2, padx=16, pady=12); qi.pack(fill="x")

        self._drm_bar = tk.Frame(qi, bg=BG2); self._drm_bar.pack(fill="x", pady=(0,6))
        self._drm_icon = tk.Label(self._drm_bar, text="🔒", bg=BG2, fg=FG3, font=FONT)
        self._drm_icon.pack(side="left")
        self._drm_lbl  = tk.Label(self._drm_bar, text="", bg=BG2, fg=FG3,
                                   font=("Segoe UI", 8))
        self._drm_lbl.pack(side="left", padx=(4,0))

        qt = tk.Frame(qi, bg=BG2); qt.pack(fill="x", pady=(0,6))
        tk.Label(qt, text="Select Qualities to Download", bg=BG2, fg=FG2,
                 font=("Segoe UI", 9)).pack(side="left")
        ttk.Button(qt, text="None", style="Ghost.TButton",
                   command=lambda: self._check_all(False)).pack(side="right", padx=(4,0))
        ttk.Button(qt, text="All", style="Ghost.TButton",
                   command=lambda: self._check_all(True)).pack(side="right")

        self._q_frame = tk.Frame(qi, bg=BG2); self._q_frame.pack(fill="x")
        self._q_hint  = tk.Label(self._q_frame,
                                  text="← paste a URL and click  Fetch Info",
                                  bg=BG2, fg=FG3, font=("Segoe UI", 9))
        self._q_hint.pack(anchor="w", pady=6)

        self._vq_rows   = []   # list of (stream_dict, BooleanVar)
        self._aq_cb     = {}   # lang_code → BooleanVar
        self._sub_cb    = {}   # lang_code → BooleanVar
        self._vq_map    = {}   # label → stream_id
        self._aq_map    = {}   # kept for compat

        # --- Output + Download card
        dc = tk.Frame(parent, bg=BG2); dc.pack(fill="x", padx=14, pady=(0,8))
        di = tk.Frame(dc, bg=BG2, padx=16, pady=14); di.pack(fill="x")
        tk.Label(di, text="Output Directory", bg=BG2, fg=FG2,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(0,5))
        or_ = tk.Frame(di, bg=BG2); or_.pack(fill="x", pady=(0,12))
        self._outdir_var = tk.StringVar(value=self.cfg.get("output_dir",""))
        tk.Entry(or_, textvariable=self._outdir_var, bg=BG3, fg=FG,
                  insertbackground=ACC3, font=MONO, relief="flat", bd=0
                  ).pack(side="left", fill="x", expand=True, ipady=6, padx=(0,10))
        ttk.Button(or_, text="Browse", style="Ghost.TButton",
                   command=lambda: self._outdir_var.set(
                       filedialog.askdirectory() or self._outdir_var.get())
                   ).pack(side="left")

        tk.Frame(di, bg=BG3, height=1).pack(fill="x", pady=(0,12))

        br2 = tk.Frame(di, bg=BG2); br2.pack(fill="x")
        self._dl_btn = ttk.Button(br2, text="⬇  Download", command=self._start_download)
        self._dl_btn.pack(side="left")
        ttk.Button(br2, text="📂 Open Folder", style="Ghost.TButton",
                   command=lambda: os.startfile(self._outdir_var.get())
                   ).pack(side="left", padx=10)
        self._dl_status = tk.Label(br2, text="", bg=BG2, fg=FG2, font=("Segoe UI",9))
        self._dl_status.pack(side="left")

        pr = tk.Frame(di, bg=BG2); pr.pack(fill="x", pady=(12,0))
        self._prog = ttk.Progressbar(pr, style="Prog.Horizontal.TProgressbar",
                                      orient="horizontal", mode="indeterminate", maximum=100)
        self._prog.pack(fill="x", expand=True)
        self._prog_txt = tk.Label(di, text="", bg=BG2, fg=FG2, font=("Segoe UI",8))
        self._prog_txt.pack(anchor="w", pady=(4,0))

        # --- Log (collapsible)
        lh = tk.Frame(parent, bg=BG, cursor="hand2")
        lh.pack(fill="x", padx=14, pady=(4,0))
        self._log_lbl_var = tk.StringVar(value="▸  Show log")
        self._log_lbl = tk.Label(lh, textvariable=self._log_lbl_var,
                                   bg=BG, fg=FG2, font=("Segoe UI",9), cursor="hand2")
        self._log_lbl.pack(side="left", pady=3, padx=2)
        for w in (lh, self._log_lbl):
            w.bind("<Button-1>", lambda e: self._toggle_log())

        self._log_frame = tk.Frame(parent, bg=BG)
        self._log_txt = tk.Text(self._log_frame, height=10, state="disabled",
                                 bg="#080a11", fg="#6a6aaa", font=("Consolas",8),
                                 borderwidth=0, insertbackground=FG, wrap="word",
                                 selectbackground=ACC2, selectforeground="#fff")
        _lsb = tk.Scrollbar(self._log_frame, command=self._log_txt.yview)
        self._log_txt.configure(yscrollcommand=_lsb.set)
        _lsb.pack(side="right", fill="y")
        self._log_txt.pack(fill="both", expand=True, padx=(14,0), pady=(3,10))
        self._log_open = False

        self._stream_info = {}   # populated by fetch_info

    def _log(self, msg):
        def _do():
            self._log_txt.configure(state="normal")
            self._log_txt.insert("end", msg + "\n")
            self._log_txt.see("end")
            self._log_txt.configure(state="disabled")
        self.after(0, _do)

    def _set_text(self, widget, txt):
        widget.configure(state="normal")
        widget.delete("1.0","end")
        widget.insert("end", txt)
        widget.configure(state="disabled")

    # --- Log toggle
    def _toggle_log(self):
        if self._log_open:
            self._log_frame.pack_forget()
            self._log_lbl_var.set("▸  Show log")
        else:
            self._log_frame.pack(fill="both", expand=True)
            self._log_lbl_var.set("▾  Hide log")
        self._log_open = not self._log_open

    # --- Video quality all/none
    def _check_all(self, val):
        for _, var in self._vq_rows:
            var.set(val)

    # --- Mini inline checkbox (for audio / subtitle track rows)
    def _make_mini_cb(self, parent, var, label, color=None):
        color = color or FG2
        c = tk.Canvas(parent, width=14, height=14, bg=BG2,
                      highlightthickness=0, cursor="hand2")
        c.pack(side="left", padx=(0, 2))

        def _draw():
            c.delete("all")
            if var.get():
                c.create_rectangle(1, 1, 13, 13, fill=color, outline=color)
                c.create_line(3, 7, 6, 10, 11, 4, fill="#000", width=2)
            else:
                c.create_rectangle(1, 1, 13, 13, fill="", outline=BG4)

        var.trace_add("write", lambda *_: _draw())
        _draw()

        def _toggle(_e=None):
            var.set(not var.get())

        c.bind("<Button-1>", _toggle)

        lbl_w = tk.Label(parent, text=label, bg=BG2, fg=color,
                         font=("Segoe UI", 8), cursor="hand2")
        lbl_w.pack(side="left", padx=(0, 10))
        lbl_w.bind("<Button-1>", _toggle)

    # --- Rebuild quality panel after MPD parse
    def _update_quality_checks(self, video_streams, audio_streams, sub_streams=None,
                               duration_ms=0):
        sub_streams = sub_streams or []

        for w in self._q_frame.winfo_children():
            w.destroy()
        self._vq_rows.clear()
        self._aq_cb.clear()
        self._sub_cb.clear()
        self._vq_map.clear()
        self._aq_map.clear()

        is_drm = self._stream_info.get("is_drm", False)
        # Grab duration - prefer passed arg, fallback to stream_info
        _dur_ms  = duration_ms or self._stream_info.get("duration_ms", 0)
        _dur_s   = _dur_ms // 1000
        _dur_h   = _dur_s  // 3600
        _dur_m   = (_dur_s % 3600) // 60
        _runtime = (f"{_dur_h}h {_dur_m:02d}m" if _dur_h else
                    f"{_dur_m}m" if _dur_m else "")
        # Store so Est. Size calc uses it
        self._stream_info["duration_ms"] = _dur_ms

        drm_txt = "DRM: Widevine encrypted  •  Auto-fetching keys…"
        if _runtime:
            drm_txt += f"   ·   Runtime: {_runtime}"
        if is_drm:
            self._drm_icon.configure(text="🔒", fg=YLW)
            self._drm_lbl.configure(text=drm_txt, fg=YLW)
        else:
            plain_txt = "DRM: Plain stream - no decryption needed"
            if _runtime:
                plain_txt += f"   ·   Runtime: {_runtime}"
            self._drm_icon.configure(text="🔓", fg=GRN)
            self._drm_lbl.configure(text=plain_txt, fg=GRN)

        # --- Audio mini-checkbox row
        _lang_colors = {
            "hin": ACC3, "tam": GRN, "tel": YLW, "mal": ORG,
            "kan": "#e060c0", "ben": "#60c0e0",
        }
        if audio_streams:
            aud_row = tk.Frame(self._q_frame, bg=BG2)
            aud_row.pack(fill="x", pady=(0, 4))
            tk.Label(aud_row, text="Audio:", bg=BG2, fg=FG2,
                     font=("Segoe UI", 8)).pack(side="left", padx=(0, 6))
            for s in audio_streams:
                lang = s.get("lang", "und").lower()
                col  = _lang_colors.get(lang, FG2)
                var  = tk.BooleanVar(value=True)
                self._aq_cb[lang] = var
                self._aq_map[s.get("label", lang)] = s.get("id", "")
                self._make_mini_cb(aud_row, var, lang.upper(), col)

        # --- Subtitle mini-checkbox row
        if sub_streams:
            sub_row = tk.Frame(self._q_frame, bg=BG2)
            sub_row.pack(fill="x", pady=(0, 4))
            tk.Label(sub_row, text="Subs:", bg=BG2, fg=FG2,
                     font=("Segoe UI", 8)).pack(side="left", padx=(0, 6))
            for s in sub_streams:
                lang = s.get("lang", "und").lower()
                var  = tk.BooleanVar(value=False)
                self._sub_cb[lang] = var
                self._make_mini_cb(sub_row, var, lang.upper(), ACC3)

        tk.Frame(self._q_frame, bg=BG3, height=1).pack(fill="x", pady=(2, 6))

        # --- Column header row
        hdr = tk.Frame(self._q_frame, bg=BG2)
        hdr.pack(fill="x", padx=4, pady=(0, 2))
        for txt, w in [("Quality", 80), ("Resolution", 110), ("Bitrate", 100), ("Est. Size", 90)]:
            tk.Label(hdr, text=txt, bg=BG2, fg=FG3,
                     font=("Segoe UI", 8), width=w // 8, anchor="w").pack(side="left")

        # --- Video CheckRow rows
        _ht_colors = {1080: ACC3, 720: GRN, 480: YLW, 360: ORG}
        streams_sorted = sorted(video_streams,
                                key=lambda s: s.get("height", 0), reverse=True)
        for i, s in enumerate(streams_sorted):
            ht    = s.get("height", 0)
            wd    = s.get("width", 0)
            kbps  = s.get("kbps", 0)
            col   = _ht_colors.get(ht, FG2)
            q_lbl = f"{ht}p" if ht else s.get("res", "?")
            r_lbl = f"{wd}×{ht}" if wd and ht else "-"
            b_lbl = f"{kbps/1000:.1f} Mbps" if kbps >= 1000 else f"{kbps} Kbps"
            # Est. Size = bitrate (kbps) × duration_s / 8 → bytes → MB
            _dur_secs = _dur_ms // 1000 if _dur_ms else 0
            if kbps and _dur_secs:
                est_bytes = (kbps * 1000 / 8) * _dur_secs   # bytes
                if est_bytes >= 1_073_741_824:                # ≥ 1 GB
                    e_lbl = f"~{est_bytes/1_073_741_824:.2f} GB"
                else:
                    e_lbl = f"~{est_bytes/1_048_576:.0f} MB"
            else:
                e_lbl = "-"
            var    = tk.BooleanVar(value=(i == 0))   # default top quality selected
            row    = CheckRow(self._q_frame, var, q_lbl,
                              res_label=r_lbl, bit_label=b_lbl, size_label=e_lbl,
                              color=col, is_top=(i == 0))
            row.pack(fill="x", pady=1)
            self._vq_rows.append((s, var))
            self._vq_map[s.get("label", q_lbl)] = s.get("id", "")

    def _fetch_info(self):
        if not self._session.get("token"):
            messagebox.showerror("Error","Load token file first in the Login tab"); return
        url = self._url_var.get().strip()
        if not url:
            messagebox.showerror("Error","Paste a SonyLIV URL"); return
        self._prog.start(12)
        threading.Thread(target=self._do_fetch_info, args=(url,), daemon=True).start()

    def _do_fetch_info(self, url):
        try:
            cid = extract_content_id(url)
            if not cid:
                self._log("[✗] Could not extract content ID from URL"); self._prog.stop(); return
            self._log(f"[...] Content ID: {cid}")

            sess       = self._session
            cookies    = {}          # Bearer auth only - no cookies needed
            dev_id     = sess["device_id"]
            contact_id = sess.get("contact_id","") or "0"

            # --- Resolve bundle ID → actual playable stream ID
            # SonyLIV movie/show URLs embed a bundle/parent ID (e.g. 1590016456).
            # The VIDEOURL API needs the real playable asset ID (e.g. 1090539851).
            # USER/SUGGESTION resolves this mapping via sony://asset/<id> deep link.
            self._log("[...] Resolving playable content ID …")
            cid, _resolved_title, _resolved_dur_ms = resolve_playable_id(cid, contact_id, dev_id, cookies, log_cb=self._log)

            # --- Auto-fetch contactId from GETPROFILE if not in cookies
            if contact_id == "0":
                import hashlib, uuid as _uuid
                tmp_session = hashlib.md5(str(_uuid.uuid4()).encode()).hexdigest() + f"-{int(time.time()*1000)}"
                self._log("[...] contactId not in cookies - calling GETPROFILE …")
                try:
                    contact_id = fetch_contact_id_from_api(dev_id, tmp_session, cookies,
                                                           log_cb=self._log)
                    if contact_id and contact_id != "0":
                        sess["contact_id"] = contact_id
                        self._session["contact_id"] = contact_id
                        self._log(f"[✓] contactId from GETPROFILE: {contact_id}")
                    else:
                        self._log("[!] GETPROFILE returned no contactId - will try anonymous")
                except Exception as gp_ex:
                    self._log(f"[!] GETPROFILE error: {gp_ex}")

            # --- Try all Indian region clusters - SR is fixed, cluster varies
            # /AGL/5.0/SR/ENG/WEB/IN/{cluster}/CONTENT/VIDEOURL/VOD/
            # KL=Kerala, TN=Tamil Nadu, AP=Andhra, TG=Telangana, MH=Maharashtra
            # KA=Karnataka, GJ=Gujarat, DL=Delhi, WB=West Bengal, etc.
            CLUSTERS = ["AP","AR","AS","BR","CH","DL","GA","GJ","HR","HP",
                        "JH","JK","KA","KL","LD","MH","ML","MN","MP","MZ",
                        "NL","OD","PB","PY","RJ","SK","TG","TN","TR","UK",
                        "UP","WB"]
            resp = None
            _debug_logged = 0  # log first 3 unique errors verbosely
            _seen_errors = {}  # err → first cluster that gave it
            for cluster in CLUSTERS:
                try:
                    r = fetch_video_url(cid, contact_id, dev_id, cookies, cluster)
                    # Success = resultObj is non-empty AND no error
                    err = r.get("errorDescription","") or r.get("message","") or ""
                    code = r.get("resultCode","")
                    has_obj = bool(r.get("resultObj"))

                    if err and err not in _seen_errors:
                        _seen_errors[err] = cluster
                        self._log(f"[DBG/{cluster}] code={code} err={err!r} hasObj={has_obj}")
                        if _debug_logged < 2:
                            self._log(f"[DBG/{cluster}] raw={json.dumps(r)[:400]}")
                            _debug_logged += 1

                    # Skip conditions: wrong cluster routing OR content-not-found on this node
                    skip_codes = {"404-10143", "404-10144", "404-10145"}
                    is_cluster_miss = (
                        "cluster" in err.lower()
                        or "not found" in err.lower()
                        or err in skip_codes
                        or (code == "KO" and not has_obj)
                    )
                    if has_obj and code != "KO":
                        self._log(f"[✓] Got stream with cluster={cluster}")
                        resp = r
                        break
                    elif is_cluster_miss:
                        continue  # silent skip - routing miss
                    else:
                        # Real API error (auth, geo-block, concurrency, etc.) - stop and surface
                        self._log(f"[!] cluster={cluster} HARD error: code={code} err={err!r}")
                        self._log(f"[!] raw={json.dumps(r)[:600]}")
                        resp = r
                        break
                except Exception as ex:
                    if _debug_logged < 3:
                        self._log(f"[!] cluster={cluster} exception: {ex}")
                        _debug_logged += 1

            if not resp:
                self._log("[✗] All clusters returned routing-miss (cluster/not-found) - Sony may require re-login or content not available in your region")
                self._log(f"[DBG] Unique errors seen: {_seen_errors}")
                self._prog.stop(); return
            self._log(f"[DEBUG] Raw resp keys: {list(resp.keys())} | resultCode={resp.get('resultCode')}")

            info = parse_stream_info(resp)
            # Override title with the one from SUGGESTION/DETAIL-V2 if better
            if _resolved_title and (not info.get("title") or info.get("title") == "SonyLIV_Video"):
                info["title"] = _resolved_title
            # Prefer duration from resolve_playable_id (SUGGESTION/DETAIL-V2) over VIDEOURL
            if _resolved_dur_ms and not info.get("duration_ms"):
                info["duration_ms"] = _resolved_dur_ms
            self._stream_info = info

            # --- Populate quality panel from MPD
            if info.get("mpd"):
                self._log("[...] Parsing MPD streams for quality selector …")
                try:
                    streams = parse_mpd_streams(info["mpd"], cookies, log_cb=self._log)
                    self._stream_info["streams"] = streams
                    self._vq_map = {s["label"]: s["id"] for s in streams["video"]}
                    self._aq_map = {s["label"]: s["id"] for s in streams["audio"]}
                    nv = len(streams["video"]); na = len(streams["audio"])
                    ns = len(streams.get("subs", []))
                    # --- Merge API-sourced subtitle URLs (VTT from CDN, not in MPD)
                    api_subs = info.get("api_subs", [])
                    for asub in api_subs:
                        if not any(s.get("lang","").lower() == asub["lang"].lower()
                                   for s in streams.get("subs", [])):
                            streams.setdefault("subs", []).append({
                                "id":   asub["lang"],
                                "lang": asub["lang"],
                                "label": f"{asub['name']} (API)",
                                "url":  asub["url"],   # direct VTT download
                                "source": "api"
                            })
                    ns_total = len(streams.get("subs", []))
                    self._log(f"[✓] Found {nv} video, {na} audio, {ns} MPD-sub + {len(api_subs)} API-sub streams ({ns_total} total subs)")
                    # --- Duration from API (content_duration in ms)
                    dur_ms = info.get("duration_ms", 0)
                    if dur_ms:
                        dur_s  = dur_ms // 1000
                        dur_h  = dur_s  // 3600
                        dur_m  = (dur_s % 3600) // 60
                        dur_s2 = dur_s  % 60
                        dur_str = (f"{dur_h}h {dur_m:02d}m {dur_s2:02d}s" if dur_h
                                   else f"{dur_m}m {dur_s2:02d}s")
                        self._log(f"[✓] Video duration: {dur_str}")
                        self._stream_info["duration_str"] = dur_str
                    self.after(0, lambda sv=streams["video"],
                                          sa=streams["audio"],
                                          ss=streams.get("subs",[]),
                                          dm=dur_ms:
                               self._update_quality_checks(sv, sa, ss, duration_ms=dm))
                except Exception as qex:
                    self._log(f"[!] Quality parse error: {qex}")

            drm = "DRM 🔐" if info["is_drm"] else "Non-DRM ✅"
            dur_str = self._stream_info.get("duration_str", "")
            dur_tag = f" · {dur_str}" if dur_str else ""
            self._log(f"[✓] {drm} - {info['title']}{dur_tag}")
            if not info['mpd']:
                # Dump raw keys to help debug
                result_keys = list(resp.get('resultObj',{}).keys())
                vd_keys = list(resp.get('resultObj',{}).get('videoDetails',{}).keys())
                self._log(f"[!] No stream URL - resultObj keys: {result_keys}")
                self._log(f"[!] videoDetails keys: {vd_keys}")
                self._log(f"[!] Full response: {json.dumps(resp)[:500]}")
        except Exception as ex:
            self._log(f"[✗] {ex}")
        finally:
            self.after(0, self._prog.stop)

    def _start_download(self):
        if not self._session.get("token"):
            messagebox.showerror("Error","Load token file first in the Login tab"); return
        url = self._url_var.get().strip()
        if not url:
            messagebox.showerror("Error","Enter a URL"); return

        out_dir = self._outdir_var.get().strip() or self.cfg["output_dir"]
        os.makedirs(out_dir, exist_ok=True)
        self.cfg["output_dir"] = out_dir
        save_cfg(self.cfg)

        self._dl_btn.configure(state="disabled", text="Downloading …")
        self._prog.start(12)
        threading.Thread(target=self._do_download, args=(url, out_dir), daemon=True).start()

    def _do_download(self, url, out_dir):
        try:
            engine = self.cfg.get("engine","N_m3u8DL-RE")

            # If we already fetched stream info, use it; else fetch now
            _api_title = ""  # filled by resolve_playable_id if we call it
            if not self._stream_info.get("mpd"):
                import hashlib, uuid as _uuid
                cid = extract_content_id(url)
                sess = self._session
                contact_id = sess.get("contact_id","0") or "0"
                if contact_id == "0":
                    tmp_s = hashlib.md5(str(_uuid.uuid4()).encode()).hexdigest() + f"-{int(time.time()*1000)}"
                    contact_id = fetch_contact_id_from_api(sess["device_id"], tmp_s, {})
                    if contact_id != "0":
                        sess["contact_id"] = contact_id
                cid, _api_title, _api_dur_ms = resolve_playable_id(cid, contact_id, sess["device_id"],
                                                                   {}, log_cb=self._log)
                CLUSTERS = ["AP","AR","AS","BR","CH","DL","GA","GJ","HR","HP",
                            "JH","JK","KA","KL","LD","MH","ML","MN","MP","MZ",
                            "NL","OD","PB","PY","RJ","SK","TG","TN","TR","UK",
                            "UP","WB"]
                resp = None
                for cluster in CLUSTERS:
                    try:
                        r = fetch_video_url(cid, contact_id,
                                            sess["device_id"], {}, cluster)
                        err  = r.get("errorDescription","") or r.get("message","")
                        code = r.get("resultCode","")
                        skip_codes = {"404-10143", "404-10144", "404-10145"}
                        is_miss = (
                            "cluster" in err.lower()
                            or "not found" in err.lower()
                            or err in skip_codes
                            or (code == "KO" and not r.get("resultObj"))
                        )
                        if is_miss:
                            continue
                        resp = r
                        break
                    except: pass
                if resp and resp.get("resultObj"):
                    parsed = parse_stream_info(resp)
                    # Apply title from SUGGESTION if videoURL gave no real title
                    if _api_title and (not parsed.get("title") or parsed.get("title") == "SonyLIV_Video"):
                        parsed["title"] = _api_title
                    # Prefer duration from resolve_playable_id over VIDEOURL (which has 0)
                    if _api_dur_ms and not parsed.get("duration_ms"):
                        parsed["duration_ms"] = _api_dur_ms
                    self._stream_info = parsed

            info  = self._stream_info
            mpd   = info.get("mpd","")
            lic   = info.get("license","")
            kid   = info.get("kid","")
            # Prefer title from SUGGESTION/DETAIL-V2 (API returns proper name),
            # fallback to whatever the videoURL response included, then generic
            title = _api_title or info.get("title","") or "SonyLIV_Video"

            if not mpd:
                self._log("[!] No MPD found - trying yt-dlp fallback …")
                _tok = (self._session.get("token") or {}).get("access_token", "")
                ok = run_ytdlp(url, out_dir, self.cfg,
                               self._log, access_token=_tok)
            elif engine == "N_m3u8DL-RE":
                # --- Read selections from Hotstar-style checkboxes
                sel_vids = [s for s, var in self._vq_rows if var.get()]

                sel_aud_langs = [lang for lang, var in self._aq_cb.items() if var.get()]
                sel_sub_langs = [lang for lang, var in self._sub_cb.items() if var.get()]

                # video: pick first checked if exactly one; else let engine pick best
                video_id = sel_vids[0]["id"] if len(sel_vids) == 1 else None
                if sel_vids:
                    self._log(f"[✓] Video quality: {sel_vids[0].get('height','?')}p "
                              f"{sel_vids[0].get('kbps','?')} Kbps")
                else:
                    self._log("[!] No video quality checked - using best")

                if sel_aud_langs:
                    self._log(f"[✓] Audio langs: {', '.join(sel_aud_langs)}")
                if sel_sub_langs:
                    self._log(f"[✓] Subtitle langs: {', '.join(sel_sub_langs)}")

                # --- Build smart filename
                _sel_vid = sel_vids[0] if sel_vids else None
                _quality = f"{_sel_vid['height']}p" if _sel_vid and _sel_vid.get("height") else "best"

                _all_aud_list = self._stream_info.get("streams", {}).get("audio", [])
                if sel_aud_langs:
                    _langs = "+".join(sorted(set(sel_aud_langs)))
                else:
                    _langs_set = sorted(set(
                        s["lang"].lower() for s in _all_aud_list
                        if s.get("lang") and s["lang"].lower() not in ("und", "")
                    ))
                    _langs = "+".join(_langs_set) if _langs_set else "und"

                _codec = "H264"
                if _sel_vid:
                    _sid = (_sel_vid.get("id") or "").lower()
                    if "hev" in _sid or "hevc" in _sid or "hvc" in _sid:
                        _codec = "H265"
                    elif "av1" in _sid:
                        _codec = "AV1"
                    elif "vp9" in _sid:
                        _codec = "VP9"

                _sel_aud_s = _all_aud_list[0] if _all_aud_list else None
                _abr = f"{_sel_aud_s['kbps']}kbps" if _sel_aud_s and _sel_aud_s.get("kbps") else "unkbps"

                _clean_title = re.sub(r'[\\/:*?"<>|]', '', title).strip().replace(' ', '_')
                smart_name   = f"{_clean_title}_{_quality}_{_langs}_{_codec}_{_abr}"
                self._log(f"[✓] Filename: {smart_name}.mkv")

                ok, _ = run_n_m3u8dl(mpd, lic, smart_name, out_dir, self.cfg, self._log,
                                      cookies=self._session.get("cookies", {}), kid=kid,
                                      video_id=video_id, audio_langs=sel_aud_langs,
                                      sub_langs=sel_sub_langs,
                                      api_subs=self._stream_info.get("api_subs", []))
            elif engine == "yt-dlp":
                _tok2 = (self._session.get("token") or {}).get("access_token", "")
                ok = run_ytdlp(url, out_dir, self.cfg, self._log, access_token=_tok2)
            else:
                # ffmpeg fallback
                out_file = os.path.join(out_dir, re.sub(r'[\\/:*?"<>|]','_',title)+".mp4")
                cmd = [self.cfg["ffmpeg_exe"], "-i", mpd, "-c", "copy", out_file, "-y"]
                self._log(f"[CMD] {' '.join(cmd)}")
                proc = subprocess.run(cmd, capture_output=True, text=True)
                self._log(proc.stdout); self._log(proc.stderr)
                ok = proc.returncode == 0

            if ok:
                self._log(f"\n[✓] Done! Saved to: {out_dir}")
                self.after(0, lambda: messagebox.showinfo("Done", f"Saved to:\n{out_dir}"))
            else:
                self._log("[✗] Download failed - check log above")
        except Exception as ex:
            self._log(f"[✗] {ex}")
        finally:
            self.after(0, self._prog.stop)
            self.after(0, lambda: self._dl_btn.configure(state="normal", text="⬇  Download"))

    # --- SETTINGS TAB
    def _build_settings(self, parent):
        scroll = tk.Frame(parent, bg=BG)
        scroll.pack(fill="both", expand=True, padx=30, pady=16)

        tk.Label(scroll, text="Settings", font=("Segoe UI",14,"bold"),
                 bg=BG, fg=ACC2).pack(anchor="w")

        eng_card = tk.Frame(scroll, bg=BG2); eng_card.pack(fill="x", pady=(10,6))
        tk.Label(eng_card, text="-- Download Engine --", font=FONTL, bg=BG2, fg=FG2).pack(anchor="w", padx=14, pady=(8,4))
        eng_row = tk.Frame(eng_card, bg=BG2); eng_row.pack(fill="x", padx=14, pady=(0,10))
        self._engine_var = tk.StringVar(value=self.cfg.get("engine","N_m3u8DL-RE"))
        for eng, desc in [
            ("N_m3u8DL-RE", "Fastest + inline DRM"),
            ("yt-dlp",      "Good fallback - no DRM key inject"),
            ("ffmpeg",      "Slow but stable - no DRM key inject"),
        ]:
            f = tk.Frame(eng_row, bg=BG3 if self._engine_var.get()==eng else BG2,
                         relief="flat", bd=1)
            f.pack(side="left", padx=4, pady=2, ipadx=10, ipady=6)
            tk.Radiobutton(f, text=f"  {eng}\n  {desc}", font=FONTL,
                           variable=self._engine_var, value=eng,
                           bg=BG2, fg=FG, selectcolor=BG3,
                           activebackground=BG2, command=self._save_settings).pack()

        paths_card = tk.Frame(scroll, bg=BG2); paths_card.pack(fill="x", pady=6)
        tk.Label(paths_card, text="-- Paths --", font=FONTL, bg=BG2, fg=FG2).pack(anchor="w", padx=14, pady=(8,4))

        self._path_vars = {}
        fields = [
            ("output_dir",      "Output Folder",       True,  "dir"),
            ("n_m3u8dl_exe",    "N_m3u8DL-RE exe",     False, "exe"),
            ("ytdlp_exe",       "yt-dlp exe",           False, "exe"),
            ("ffmpeg_exe",      "ffmpeg exe",           False, "exe"),
            ("wvd_file",        "WVD Device File",      False, "wvd"),
            ("shaka_exe",       "Shaka Packager exe",   False, "exe"),
            ("mp4decrypt_exe",  "mp4decrypt exe",       False, "exe"),
            ("mkvmerge_exe",    "mkvmerge exe",         False, "exe"),
            ("thread_count",    "Download Threads",     False, "int"),
        ]
        for key, label, is_dir, typ in fields:
            row = tk.Frame(paths_card, bg=BG2); row.pack(fill="x", padx=14, pady=3)
            tk.Label(row, text=label, font=FONTL, bg=BG2, fg=FG2, width=20, anchor="w").pack(side="left")
            var = tk.StringVar(value=self.cfg.get(key,""))
            self._path_vars[key] = var
            tk.Entry(row, textvariable=var, font=FONTL, bg=BG3, fg=FG,
                     insertbackground=FG, relief="flat",
                     highlightthickness=1, highlightbackground=BG3).pack(side="left", fill="x", expand=True, ipady=4)
            def _browse(k=key, d=is_dir):
                if d:
                    p = filedialog.askdirectory()
                else:
                    p = filedialog.askopenfilename()
                if p: self._path_vars[k].set(p)
            if typ != "int":   # no Browse button for plain number fields
                tk.Button(row, text="Browse", font=FONTL, bg=BG3, fg=FG2,
                          relief="flat", cursor="hand2", padx=8,
                          command=_browse).pack(side="left", padx=(6,0))

        drm_card = tk.Frame(scroll, bg=BG2); drm_card.pack(fill="x", pady=6)
        tk.Label(drm_card, text="-- DRM Decrypt Tool --", font=FONTL, bg=BG2, fg=FG2).pack(anchor="w", padx=14, pady=(8,4))
        drm_row = tk.Frame(drm_card, bg=BG2); drm_row.pack(fill="x", padx=14, pady=(0,10))
        self._drm_var = tk.StringVar(value=self.cfg.get("drm_tool","auto"))
        for val, desc in [("auto","Auto"), ("mp4decrypt","mp4decrypt\n(Bento4)"), ("shaka","Shaka Packager\n(per-track)")]:
            tk.Radiobutton(drm_row, text=f"  {desc}", font=FONTL,
                           variable=self._drm_var, value=val,
                           bg=BG2, fg=FG, selectcolor=BG3,
                           activebackground=BG2,
                           command=self._save_settings).pack(side="left", padx=8)

        tk.Button(scroll, text="  Save Settings  ", font=FONTB,
                  bg=ACC, fg="white", relief="flat", padx=14, pady=8,
                  cursor="hand2", command=self._save_settings).pack(anchor="w", pady=14)

    def _save_settings(self):
        self.cfg["engine"]   = self._engine_var.get()
        self.cfg["drm_tool"] = self._drm_var.get()
        for k, var in self._path_vars.items():
            v = var.get()
            # Coerce numeric fields from string
            if k == "thread_count":
                try: v = int(v)
                except ValueError: v = 32
            self.cfg[k] = v
        save_cfg(self.cfg)

# --- entry point
if __name__ == "__main__":
    try:
        import pywidevine
    except ImportError:
        try:
            subprocess.check_call([sys.executable,"-m","pip","install","pywidevine","-q"])
        except: pass
    App().mainloop()
