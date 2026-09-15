#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TRIDENT :: trident_utils.py — v1.0.0
#  Shared utilities for the entire TRIDENT suite.
# -----------------------------------------------------------------------------
#  What's here:
#    · Colors + logging (single source of truth)
#    · Target normalization + filename safety
#    · Atomic JSON I/O (+ optional gzip)
#    · .env loader with strict parsing + os.environ merge
#    · AI provider registry (6 hosted + Ollama-local)
#    · API key resolver — which providers are usable RIGHT NOW
#    · System resource auditor (CPU / RAM / disk / load)
#    · HTTP session (pooling, retry, proxy, UA rotation)
#    · Header parsing (Burp paste → dict, hop-by-hop stripped)
#    · PAYLOAD VAULT — base64 & XOR obfuscation for AV-hostile payloads
#    · Transparent payload loading (.b64 / .xor / .yaml autodetect)
#    · Placeholder substitution
#    · WAF / cloud / DBMS fingerprinting
#    · JSON path get/set
#    · Formatters
#    · `doctor` — full application health report
#
#  Why the vault?
#    Some hosting environments flag SQLi/XSS payload YAML as malware and
#    quarantine the files. Encoding them (b64 or XOR+b64) sidesteps naive
#    content scanners. TRIDENT decodes in-memory at runtime.
# =============================================================================

import os
import re
import sys
import gzip
import json
import time
import uuid
import base64
import shutil
import random
import socket
import hashlib
import platform
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from shutil import which as _which
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)

# -----------------------------------------------------------------------------
#  Third-party deps (all soft — will warn but not die)
# -----------------------------------------------------------------------------
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

try:
    import psutil as _psutil
except ImportError:
    _psutil = None


# =============================================================================
#  CONSTANTS
# =============================================================================
VERSION = "1.0.0"

ROOT = Path(__file__).resolve().parent
PAYLOAD_DIR = ROOT / "payloads"
RESPONSE_DIR = ROOT / "responses"
HELPER_DIR = ROOT / "helpers"
TEMPLATE_DIR = ROOT / "templates"
OUTPUT_DIR = ROOT / "output"
REPORT_DIR = ROOT / "reports"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (TRIDENT; BugBounty) AppleWebKit/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 "
    "Safari/604.1",
]

DEFAULTS = {
    "attacker_domain":   "beardedviking.org",
    "collab_host":       "oast.beardedviking.org",
    "canary_host":       "redirect.beardedviking.org",
    "canary_string":     "TRIDENT-CANARY-LANDED",
    "alert_payload":     "alert(document.domain)",
    "oob_log_file":      None,
    "use_subdomain_oob": False,
    "max_workers":       8,
    "delay":             0.15,
    "timeout":           12,
    "use_browser":       False,
    "provider_filter":   None,
    "proxy":             None,
    "rotate_user_agent": False,
    "retry_transient":   True,
    "gzip_findings":     False,
}

#  XOR obfuscation key — MUST stay constant or .xor files won't decode.
#  Change this only if you regenerate every .xor file.
_XOR_KEY = b"TRIDENT::v1::KEYSTREAM::a7f3c1"

#  Vault file extensions (in priority order for loading)
VAULT_EXT_PRIORITY = (".xor", ".b64", ".yaml")

#  Header handling
SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token", "proxy-authorization",
    "x-amz-security-token", "x-goog-api-key", "x-roblox-csrf",
})

HOP_BY_HOP_HEADERS = frozenset({
    "content-length", "content-encoding", "transfer-encoding",
    "connection", "keep-alive", "te", "trailer", "upgrade",
    "host", "accept-encoding", "proxy-authorization",
})

_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                 "OPTIONS", "CONNECT", "TRACE")

_REQUEST_LINE_RE = re.compile(
    r"^(?:" + "|".join(_HTTP_METHODS) + r")\s+\S+\s+HTTP/\d(?:\.\d)?\s*$"
)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# =============================================================================
#  AI PROVIDER REGISTRY
# =============================================================================
AI_PROVIDERS = {
    "deepseek": {
        "label":       "DeepSeek",
        "env_vars":    ["DEEPSEEK_API_KEY", "DEEPSEEK_KEY", "DEEPSEEK_TOKEN"],
        "base_url":    "https://api.deepseek.com/v1",
        "default":     "deepseek-chat",
        "models":      ["deepseek-chat", "deepseek-reasoner"],
        "pricing":     "paid",
        "notes":       "Reasoning-heavy. Excellent for exploit chains.",
        "probe":       "GET /models",
    },
    "groq": {
        "label":       "Groq",
        "env_vars":    ["GROQ_API_KEY", "GROQ_KEY"],
        "base_url":    "https://api.groq.com/openai/v1",
        "default":     "llama-3.3-70b-versatile",
        "models":      ["llama-3.3-70b-versatile", "mixtral-8x7b-32768",
                        "llama-3.1-8b-instant"],
        "pricing":     "free-tier",
        "notes":       "Fastest inference on the market. Generous free tier.",
        "probe":       "GET /models",
    },
    "gemini": {
        "label":       "Google Gemini",
        "env_vars":    ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GEMINI_API_KEY"],
        "base_url":    "https://generativelanguage.googleapis.com/v1beta",
        "default":     "gemini-2.0-flash",
        "models":      ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "pricing":     "free-tier",
        "notes":       "Huge context window. Best for large crawled pages.",
        "probe":       None,
    },
    "openai": {
        "label":       "OpenAI",
        "env_vars":    ["OPENAI_API_KEY", "OPENAI_KEY"],
        "base_url":    "https://api.openai.com/v1",
        "default":     "gpt-4o-mini",
        "models":      ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "pricing":     "paid",
        "notes":       "Broadest model range. Reliable JSON output.",
        "probe":       "GET /models",
    },
    "anthropic": {
        "label":       "Anthropic Claude",
        "env_vars":    ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        "base_url":    "https://api.anthropic.com/v1",
        "default":     "claude-sonnet-4-20250514",
        "models":      ["claude-sonnet-4-20250514", "claude-opus-4"],
        "pricing":     "paid",
        "notes":       "Best at long-form report drafting and reasoning.",
        "probe":       None,
    },
    "huggingface": {
        "label":       "Hugging Face",
        "env_vars":    ["HUGGINGFACE_API_KEY", "HUGGINGFACE_TOKEN",
                        "HF_API_KEY", "HF_TOKEN"],
        "base_url":    "https://api-inference.huggingface.co",
        "default":     "meta-llama/Llama-3.3-70B-Instruct",
        "models":      ["meta-llama/Llama-3.3-70B-Instruct"],
        "pricing":     "free-tier",
        "notes":       "Router access to hundreds of models.",
        "probe":       None,
    },
    "ollama": {
        "label":       "Ollama (local)",
        "env_vars":    ["OLLAMA_HOST"],
        "base_url":    "http://localhost:11434",
        "default":     "llama3.1",
        "models":      ["llama3.1", "qwen2.5:32b", "deepseek-coder-v2"],
        "pricing":     "local",
        "notes":       "Planned TRIDENT v2 target. Zero API cost.",
        "probe":       "GET /api/tags",
    },
}

#  Provider precedence when auto-selecting a fallback chain
PROVIDER_CHAIN = ["groq", "gemini", "deepseek", "openai",
                  "anthropic", "huggingface", "ollama"]

# =============================================================================
#  COLORS
# =============================================================================
class C:
    R  = "\033[0m";  B  = "\033[1m";  D  = "\033[2m"
    CY = "\033[38;5;51m"; GR = "\033[38;5;46m"
    YE = "\033[38;5;226m"; RE = "\033[38;5;196m"
    MA = "\033[38;5;201m"; BL = "\033[38;5;33m"
    WH = "\033[38;5;231m"; GY = "\033[38;5;240m"
    OR = "\033[38;5;208m"


# =============================================================================
#  LOGGING
# =============================================================================
def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, level="info", tag=None):
    prefix = {
        "info":  f"{C.CY}[*]{C.R}",
        "ok":    f"{C.GR}[+]{C.R}",
        "warn":  f"{C.YE}[!]{C.R}",
        "err":   f"{C.RE}[-]{C.R}",
        "scan":  f"{C.MA}[>]{C.R}",
        "hit":   f"{C.GR}[✔]{C.R}",
        "debug": f"{C.GY}[·]{C.R}",
    }.get(level, f"{C.CY}[*]{C.R}")
    t = f"{C.GY}{ts()}{C.R} "
    tag_s = f"{C.B}{C.MA}{tag}{C.R} " if tag else ""
    print(f"{t}{prefix} {tag_s}{msg}", flush=True)


def section(title):
    line = "─" * 68
    print(f"\n{C.CY}┌{line}┐{C.R}")
    print(f"{C.CY}│{C.R} {C.B}{C.WH}{title}{C.R}")
    print(f"{C.CY}└{line}┘{C.R}\n")


def banner():
    print(f"""{C.CY}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ████████╗██████╗ ██╗██████╗ ███████╗███╗   ██╗████████╗           ║
║   ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝           ║
║      ██║   ██████╔╝██║██║  ██║█████╗  ██╔██╗ ██║   ██║              ║
║      ██║   ██╔══██╗██║██║  ██║██╔══╝  ██║╚██╗██║   ██║              ║
║      ██║   ██║  ██║██║██████╔╝███████╗██║ ╚████║   ██║              ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝              ║
║                                                                      ║
║              {C.MA}T H R E E   P R O N G S{C.CY}                           ║
║         {C.D}Recon · Audit · Report — v{VERSION}{C.CY}                     ║
╚══════════════════════════════════════════════════════════════════════╝
{C.R}""")


# =============================================================================
#  TIME HELPERS
# =============================================================================
def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def now_unix():
    return int(time.time())


# =============================================================================
#  TARGET NORMALIZATION
# =============================================================================
def normalize_target(target):
    target = (target or "").strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        target = "https://" + target
    p = urlparse(target)
    domain = p.netloc.split(":")[0].lower()
    scheme = p.scheme or "https"
    return domain, f"{scheme}://{p.netloc}"


def safe_filename(s):
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(s)).strip(" .")
    if len(s) > 180:
        s = s[:180] + "_" + hashlib.md5(s.encode()).hexdigest()[:6]
    return s or "_"


def get_host(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def url_extension(url):
    try:
        path = urlparse(url).path
        if "." not in path.rsplit("/", 1)[-1]:
            return ""
        return "." + path.rsplit(".", 1)[-1].lower()
    except Exception:
        return ""


# =============================================================================
#  JSON I/O
# =============================================================================
def save_json(path, data, compress=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    use_gzip = compress or path.suffix == ".gz"
    tmp = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    if use_gzip:
        with gzip.open(tmp, "wb") as f:
            f.write(payload)
    else:
        with open(tmp, "wb") as f:
            f.write(payload)
    os.replace(tmp, path)
    return path


def load_json(path):
    path = Path(path)
    if path.suffix == ".gz" or str(path).endswith(".json.gz"):
        with gzip.open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================================
#  .ENV LOADER
# =============================================================================
_ENV_SEARCH = [
    Path(".env"),
    Path("./.env"),
    ROOT / ".env",
    ROOT.parent / ".env",
    Path.home() / ".config" / "trident" / ".env",
    Path.home() / ".trident.env",
]

_ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def find_env_file():
    for p in _ENV_SEARCH:
        try:
            if Path(p).exists() and Path(p).is_file():
                return Path(p)
        except Exception:
            continue
    return None


def parse_env_file(path):
    """Parse a KEY=VALUE .env file. Handles quotes, comments, export."""
    out = {}
    path = Path(path)
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        # Strip inline comments for unquoted values
        if not (val.startswith('"') or val.startswith("'")):
            hash_idx = val.find(" #")
            if hash_idx > -1:
                val = val[:hash_idx].rstrip()
        # Strip wrapping quotes
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key:
            out[key] = val
    return out


def load_env(merge_into_environ=False, override=False):
    """
    Locate and parse the nearest .env. Returns dict of keys.

    If merge_into_environ=True, injects values into os.environ so
    downstream libs (openai, anthropic, etc.) can read them directly.
    """
    path = find_env_file()
    data = parse_env_file(path) if path else {}
    if merge_into_environ:
        for k, v in data.items():
            if override or k not in os.environ:
                os.environ[k] = v
    return data


# =============================================================================
#  API KEY RESOLVER
# =============================================================================
def resolve_api_keys(env=None):
    """
    Return a dict of provider -> resolved key.
    Checks .env first, falls back to os.environ.
    Empty string means "not set".
    """
    if env is None:
        env = load_env()
    resolved = {}
    for name, cfg in AI_PROVIDERS.items():
        key = ""
        for var in cfg["env_vars"]:
            if env.get(var):
                key = env[var]
                break
            if os.environ.get(var):
                key = os.environ[var]
                break
        resolved[name] = key
    return resolved


def usable_providers(env=None):
    """Return list of provider names whose key is present and non-empty."""
    keys = resolve_api_keys(env)
    return [p for p, k in keys.items() if k]


def provider_summary(env=None):
    """
    Full status table: for each provider, whether it's usable, which
    env var matched, pricing, and notes.
    """
    if env is None:
        env = load_env()
    rows = []
    for name, cfg in AI_PROVIDERS.items():
        matched_var = None
        for var in cfg["env_vars"]:
            if env.get(var) or os.environ.get(var):
                matched_var = var
                break
        rows.append({
            "provider": name,
            "label":    cfg["label"],
            "usable":   bool(matched_var),
            "env_var":  matched_var,
            "pricing":  cfg["pricing"],
            "default":  cfg["default"],
            "notes":    cfg.get("notes", ""),
        })
    return rows


def pick_provider(prefer=None, env=None):
    """
    Return the best provider to use. If `prefer` is given and usable,
    return it. Otherwise return the first usable one in PROVIDER_CHAIN.
    """
    usable = set(usable_providers(env))
    if prefer and prefer in usable:
        return prefer
    for name in PROVIDER_CHAIN:
        if name in usable:
            return name
    return None


def probe_provider(name, timeout=8):
    """
    Lightweight reachability check. Only works for providers with a
    `probe` field. Returns (ok, message).
    """
    if not _HAVE_REQUESTS:
        return False, "requests not installed"
    cfg = AI_PROVIDERS.get(name)
    if not cfg:
        return False, "unknown provider"
    probe = cfg.get("probe")
    if not probe:
        return True, "no probe endpoint"

    keys = resolve_api_keys()
    key = keys.get(name)
    headers = {}
    url = cfg["base_url"] + probe.split(" ", 1)[1]

    if name == "ollama":
        # local — no auth
        pass
    elif name == "gemini":
        url = cfg["base_url"] + "/models?key=" + (key or "")
    else:
        headers["Authorization"] = f"Bearer {key}"
        if name == "anthropic":
            headers["x-api-key"] = key
            headers["anthropic-version"] = "2023-06-01"

    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False)
        if r.status_code < 400:
            return True, f"HTTP {r.status_code}"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)[:80]


# =============================================================================
#  SYSTEM RESOURCE AUDITOR
# =============================================================================
def collect_system_info():
    """
    Best-effort system snapshot. Uses psutil if available, otherwise
    falls back to stdlib + /proc + /sys.
    """
    info = {
        "hostname":   socket.gethostname(),
        "platform":   platform.platform(),
        "arch":       platform.machine(),
        "python":     platform.python_version(),
        "cpu_count":  os.cpu_count() or 0,
    }

    # Load average (unix)
    try:
        info["load_avg"] = os.getloadavg()
    except (OSError, AttributeError):
        info["load_avg"] = None

    # psutil fast path
    if _psutil is not None:
        try:
            vm = _psutil.virtual_memory()
            info["mem_total"]     = vm.total
            info["mem_available"] = vm.available
            info["mem_percent"]   = vm.percent
            info["swap_total"]    = _psutil.swap_memory().total
            du = _psutil.disk_usage(str(Path.cwd()))
            info["disk_total"]    = du.total
            info["disk_free"]     = du.free
            info["disk_percent"]  = du.percent
            boot = _psutil.boot_time()
            info["uptime_sec"]    = int(time.time() - boot)
            return info
        except Exception:
            pass

    # /proc/meminfo fallback (Linux)
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                k, _, v = line.partition(":")
                mem[k.strip()] = int(v.strip().split()[0]) * 1024
        info["mem_total"]     = mem.get("MemTotal", 0)
        info["mem_available"] = mem.get("MemAvailable", 0)
        info["mem_percent"]   = (
            round(100 * (1 - info["mem_available"] / info["mem_total"]), 1)
            if info["mem_total"] else 0
        )
    except Exception:
        pass

    # Disk via shutil
    try:
        du = shutil.disk_usage(str(Path.cwd()))
        info["disk_total"]   = du.total
        info["disk_free"]    = du.free
        info["disk_percent"] = round(100 * (1 - du.free / du.total), 1)
    except Exception:
        pass

    return info


def resource_verdict(info):
    """
    Return a tuple (level, message) summarizing whether this machine
    can comfortably run TRIDENT. Level is one of: 'ok', 'warn', 'fail'.
    """
    cpu = info.get("cpu_count", 0)
    mem_total = info.get("mem_total", 0)
    disk_free = info.get("disk_free", 0)
    mem_pct = info.get("mem_percent", 0)
    disk_pct = info.get("disk_percent", 0)

    problems = []
    if cpu and cpu < 2:
        problems.append(f"only {cpu} CPU core(s)")
    if mem_total and mem_total < 512 * 1024 * 1024:
        problems.append("less than 512 MB RAM")
    if disk_free and disk_free < 200 * 1024 * 1024:
        problems.append("less than 200 MB free disk")
    if mem_pct and mem_pct > 90:
        problems.append(f"memory {mem_pct}% used")
    if disk_pct and disk_pct > 92:
        problems.append(f"disk {disk_pct}% used")

    if not problems:
        if cpu and cpu >= 4 and mem_total >= 4 * 1024**3:
            return "ok", "Excellent — plenty of headroom for parallel scanning."
        return "ok", "Adequate for TRIDENT."
    return "warn", "Tight: " + ", ".join(problems)


# =============================================================================
#  HTTP — SESSION MANAGEMENT
# =============================================================================
_SESSION = None
_SESSION_LOCK = threading.Lock()

_THROTTLE_LAST = {}
_THROTTLE_HITS = {}
_THROTTLE_LOCK = threading.Lock()

_REQUEST_COUNT = {"total": 0, "ok": 0, "err": 0}
_REQUEST_COUNT_LOCK = threading.Lock()


def get_session(proxy=None, rotate_user_agent=False):
    global _SESSION
    if not _HAVE_REQUESTS:
        return None
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                s = requests.Session()
                s.headers.update(DEFAULT_HEADERS)
                if rotate_user_agent:
                    s.headers["User-Agent"] = random.choice(USER_AGENT_POOL)
                if proxy:
                    s.proxies.update({"http": proxy, "https": proxy})
                s.verify = False
                try:
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=32, pool_maxsize=64, max_retries=0,
                    )
                    s.mount("https://", adapter)
                    s.mount("http://", adapter)
                except Exception:
                    pass
                _SESSION = s
    return _SESSION


def reset_session():
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is not None:
            try:
                _SESSION.close()
            except Exception:
                pass
        _SESSION = None


def send_request(url, method="GET", headers=None, timeout=12,
                 allow_redirects=False, data=None, params=None, json_body=None,
                 retry=True):
    sess = get_session()
    if sess is None:
        return None

    merged = dict(DEFAULT_HEADERS)
    if headers:
        merged.update(headers)
    merged = strip_hop_by_hop(merged)

    def _attempt():
        return sess.request(
            method=method, url=url, headers=merged, timeout=timeout,
            allow_redirects=allow_redirects, data=data, params=params,
            json=json_body,
        )

    try:
        resp = _attempt()
        with _REQUEST_COUNT_LOCK:
            _REQUEST_COUNT["total"] += 1
            _REQUEST_COUNT["ok"] += 1
        return resp
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout):
        if retry and DEFAULTS.get("retry_transient", True):
            try:
                time.sleep(0.4)
                resp = _attempt()
                with _REQUEST_COUNT_LOCK:
                    _REQUEST_COUNT["total"] += 1
                    _REQUEST_COUNT["ok"] += 1
                return resp
            except Exception:
                pass
        with _REQUEST_COUNT_LOCK:
            _REQUEST_COUNT["total"] += 1
            _REQUEST_COUNT["err"] += 1
        return None
    except Exception:
        with _REQUEST_COUNT_LOCK:
            _REQUEST_COUNT["total"] += 1
            _REQUEST_COUNT["err"] += 1
        return None


def request_stats():
    with _REQUEST_COUNT_LOCK:
        return dict(_REQUEST_COUNT)


# =============================================================================
#  THROTTLE
# =============================================================================
def throttle(host, delay):
    if delay <= 0 or not host:
        return
    with _THROTTLE_LOCK:
        now = time.time()
        last = _THROTTLE_LAST.get(host, 0.0)
        wait = delay - (now - last)
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _THROTTLE_LAST[host] = now
        _THROTTLE_HITS[host] = _THROTTLE_HITS.get(host, 0) + 1


# =============================================================================
#  URL HELPERS
# =============================================================================
def inject_param(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if param not in qs:
        return None
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


# =============================================================================
#  JSON PATH
# =============================================================================
_JSON_PATH_RE = re.compile(r"\.([^\.\[\]]+)|\[(\d+)\]")


def parse_json_path(path):
    tokens = []
    for name, idx in _JSON_PATH_RE.findall(path or ""):
        if name:
            tokens.append(name)
        elif idx:
            tokens.append(int(idx))
    return tokens


def set_json_path(obj, path, value):
    tokens = parse_json_path(path)
    if not tokens:
        return obj
    cur = obj
    for i, key in enumerate(tokens):
        if i == len(tokens) - 1:
            try:
                cur[key] = value
            except Exception:
                pass
            return obj
        try:
            cur = cur[key]
        except Exception:
            return obj
    return obj


def get_json_path(obj, path, default=None):
    cur = obj
    for key in parse_json_path(path):
        try:
            cur = cur[key]
        except Exception:
            return default
    return cur


# =============================================================================
#  HEADER HANDLING
# =============================================================================
def mask_header_value(name, value):
    if not value:
        return ""
    low = (name or "").lower()
    if low in SENSITIVE_HEADERS:
        if len(value) <= 12:
            return "***"
        return f"{value[:4]}...{value[-4:]} ({len(value)} bytes)"
    return value


def strip_hop_by_hop(headers):
    if not headers:
        return {}
    return {k: v for k, v in headers.items()
            if (k or "").lower() not in HOP_BY_HOP_HEADERS}


def parse_header_block(text):
    """
    Parse a raw HTTP header block into a dict.
    Handles HTTP/1.0-3 request lines, continuations, comments, HTTP/2
    pseudo-headers, quoted values, and Burp HTTP/2 pastes.
    """
    headers = {}
    if not text:
        return headers
    last_name = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line or not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        if _REQUEST_LINE_RE.match(line):
            continue
        if line.startswith(":") and ":" in line[1:]:
            continue
        if line[0] in (" ", "\t") and last_name:
            headers[last_name] = headers.get(last_name, "") + " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if not name or not _HEADER_NAME_RE.match(name):
            continue
        headers[name] = value
        last_name = name
    return headers


def load_header_profile(path):
    path = Path(path)
    if not path.exists() or not path.is_file():
        return {}
    try:
        return parse_header_block(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


class HeaderJar:
    """Per-host header resolver. Directory layout: headers/<host>.txt"""

    def __init__(self, headers_dir, cli_headers=None):
        self.dir = Path(headers_dir)
        self.cli_headers = dict(cli_headers or {})
        self._default = {}
        self._hosts = {}
        self._loaded = False
        self._lock = threading.Lock()

    def load(self):
        with self._lock:
            self._default = strip_hop_by_hop(
                load_header_profile(self.dir / "default.txt"))
            self._hosts = {}
            if self.dir.exists():
                for p in self.dir.glob("*.txt"):
                    name = p.stem.lower()
                    if name == "default":
                        continue
                    hdrs = load_header_profile(p)
                    if hdrs:
                        self._hosts[name] = strip_hop_by_hop(hdrs)
            self._loaded = True

    def reload(self):
        self.load()

    def headers_for(self, host_or_url, extra=None):
        if not self._loaded:
            self.load()
        if "://" in (host_or_url or ""):
            try:
                host = urlparse(host_or_url).netloc.lower()
            except Exception:
                host = ""
        else:
            host = (host_or_url or "").lower()
        host_noport = host.split(":")[0]

        merged = dict(self._default)
        parts = host_noport.split(".")
        parent = ".".join(parts[-2:]) if len(parts) > 2 else None
        if parent and parent in self._hosts:
            merged.update(self._hosts[parent])
        for key in (host_noport, host):
            if key and key in self._hosts:
                merged.update(self._hosts[key])
        merged.update(self.cli_headers)
        if extra:
            merged.update(extra)
        return strip_hop_by_hop(merged)

    def profiles_loaded(self):
        out = []
        if self._default:
            out.append(("default", len(self._default)))
        for host in sorted(self._hosts):
            if self._hosts[host]:
                out.append((host, len(self._hosts[host])))
        return out


# =============================================================================
#  PAYLOAD VAULT  (the important part)
# =============================================================================
def _xor_bytes(data, key):
    """Repeating-key XOR. Symmetric — same function encodes and decodes."""
    if not key:
        return data
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def _wrap_b64(b64_bytes, width=76):
    """Wrap base64 output at fixed width for readability / host safety."""
    return b"\n".join(b64_bytes[i:i + width]
                      for i in range(0, len(b64_bytes), width))


def _unwrap_b64(b64_text):
    """Strip whitespace from base64 text."""
    return re.sub(rb"\s+", b"", b64_text)


def encode_payload_file(yaml_path, mode="b64", keep_source=True):
    """
    Encode a single .yaml into .b64 or .xor.
    mode: "b64"  -> base64 only
          "xor"  -> XOR + base64 (much harder for AV to fingerprint)
    Returns (out_path, src_size, out_size) or raises.
    """
    yaml_path = Path(yaml_path)
    if not yaml_path.exists():
        raise FileNotFoundError(yaml_path)
    raw = yaml_path.read_bytes()

    if mode == "xor":
        obfuscated = _xor_bytes(raw, _XOR_KEY)
        b64 = base64.b64encode(obfuscated)
        out_path = yaml_path.with_suffix(".xor")
    else:
        b64 = base64.b64encode(raw)
        out_path = yaml_path.with_suffix(".b64")

    wrapped = _wrap_b64(b64)
    out_path.write_bytes(wrapped + b"\n")

    if not keep_source:
        try:
            yaml_path.unlink()
        except Exception:
            pass

    return out_path, len(raw), len(wrapped)


def decode_payload_file(encoded_path, mode=None):
    """
    Decode a .b64 or .xor back into .yaml.
    mode auto-detected from extension if not given.
    Returns (out_path, src_size, out_size) or raises.
    """
    encoded_path = Path(encoded_path)
    if not encoded_path.exists():
        raise FileNotFoundError(encoded_path)

    suffix = encoded_path.suffix.lower()
    if mode is None:
        mode = "xor" if suffix == ".xor" else "b64"

    b64_raw = _unwrap_b64(encoded_path.read_bytes())
    decoded = base64.b64decode(b64_raw)

    if mode == "xor":
        decoded = _xor_bytes(decoded, _XOR_KEY)

    out_path = encoded_path.with_suffix(".yaml")
    out_path.write_bytes(decoded)
    return out_path, len(b64_raw), len(decoded)


def vault_encode_all(directory=None, mode="b64", keep_source=True):
    directory = Path(directory or PAYLOAD_DIR)
    if not directory.exists():
        return 0, [f"directory not found: {directory}"]
    yamls = sorted(directory.glob("*.yaml"))
    if not yamls:
        return 0, ["no .yaml files in payloads/"]
    encoded, errors = 0, []
    for yp in yamls:
        try:
            out, s, o = encode_payload_file(yp, mode=mode,
                                             keep_source=keep_source)
            log(f"{yp.name} -> {out.name} ({s} -> {o} B)",
                "ok", "VAULT")
            encoded += 1
        except Exception as e:
            errors.append(f"{yp.name}: {e}")
    return encoded, errors


def vault_decode_all(directory=None):
    directory = Path(directory or PAYLOAD_DIR)
    if not directory.exists():
        return 0, [f"directory not found: {directory}"]
    enc = sorted(list(directory.glob("*.b64")) +
                 list(directory.glob("*.xor")))
    if not enc:
        return 0, ["no .b64/.xor files in payloads/"]
    decoded, errors = 0, []
    for ep in enc:
        try:
            out, s, o = decode_payload_file(ep)
            log(f"{ep.name} -> {out.name} ({s} -> {o} B)", "ok", "VAULT")
            decoded += 1
        except Exception as e:
            errors.append(f"{ep.name}: {e}")
    return decoded, errors


def vault_status(directory=None):
    """
    Return dict: name -> {"yaml": bool, "b64": bool, "xor": bool}
    """
    directory = Path(directory or PAYLOAD_DIR)
    out = {}
    if not directory.exists():
        return out
    for ext, key in ((".yaml", "yaml"), (".b64", "b64"), (".xor", "xor")):
        for p in directory.glob(f"*{ext}"):
            slot = out.setdefault(p.stem, {"yaml": False, "b64": False,
                                            "xor": False})
            slot[key] = True
    return out


# =============================================================================
#  PAYLOAD LOADING  (transparent vault-aware)
# =============================================================================
def _locate_payload_file(name, directory=None):
    """
    Given a logical payload name (e.g. 'sqli'), return the highest-priority
    existing file: .xor > .b64 > .yaml
    """
    directory = Path(directory or PAYLOAD_DIR)
    for ext in VAULT_EXT_PRIORITY:
        candidate = directory / f"{name}{ext}"
        if candidate.exists():
            return candidate
    return None


def _read_payload_bytes(path):
    """Read a payload file and return raw YAML text (decoding if encoded)."""
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".yaml" or suffix == ".yml":
        return path.read_text(encoding="utf-8", errors="ignore")

    b64_raw = _unwrap_b64(path.read_bytes())
    decoded = base64.b64decode(b64_raw)

    if suffix == ".xor":
        decoded = _xor_bytes(decoded, _XOR_KEY)

    return decoded.decode("utf-8", errors="ignore")


def load_payloads(name, directory=None):
    """
    Load a payload YAML by logical name. Vault-aware: tries .xor, then
    .b64, then .yaml. Returns parsed dict or {} on failure.
    """
    if _yaml is None:
        log("pyyaml missing: pip install pyyaml", "err")
        return {}

    path = _locate_payload_file(name, directory)
    if path is None:
        log(f"payload not found: {name} (.xor/.b64/.yaml)", "warn")
        return {}

    try:
        text = _read_payload_bytes(path)
        data = _yaml.safe_load(text)
        if isinstance(data, dict):
            return data
        return {}
    except Exception as e:
        log(f"payload load error ({path.name}): {e}", "err")
        return {}


def load_responses(name, directory=None):
    """Same as load_payloads but for the responses/ directory."""
    return load_payloads(name, directory or RESPONSE_DIR)


# =============================================================================
#  PLACEHOLDER SUBSTITUTION
# =============================================================================
def substitute_placeholders(payload, attacker="", target="", subdomain="",
                            alert="", collab="", oob="", token="", extra=None):
    if not payload:
        return payload
    subs = {
        "{{ATTACKER}}":  attacker or "",
        "{{TARGET}}":    target or "",
        "{{SUBDOMAIN}}": subdomain or target or "",
        "{{ALERT}}":     alert or "alert(1)",
        "{{COLLAB}}":    collab or attacker or "",
        "{{OOB}}":       oob or "",
        "{{RANDOM}}":    token or uuid.uuid4().hex[:8],
    }
    if extra:
        for k, v in extra.items():
            subs[f"{{{{{k}}}}}"] = str(v)
    for k, v in subs.items():
        payload = payload.replace(k, v)
    return payload


# =============================================================================
#  FINGERPRINTING
# =============================================================================
WAF_SIGNATURES = {
    "cloudflare":  ["cloudflare"],
    "akamai":      ["akamai"],
    "sucuri":      ["sucuri"],
    "imperva":     ["imperva", "incapsula"],
    "awswaf":      ["aws waf", "awselb", "cloudfront"],
    "azurewaf":    ["azure front door", "azure waf"],
    "f5":          ["f5", "big-ip", "bigip"],
    "modsecurity": ["modsecurity", "mod_security"],
    "fastly":      ["fastly"],
}

CLOUD_SIGNATURES = {
    "aws":          ["amazon", "aws", "cloudfront", "elb", "route53",
                     "s3.amazonaws", "elasticbeanstalk"],
    "gcp":          ["google cloud", "gcp", "googleusercontent",
                     "appspot", "google frontend"],
    "azure":        ["azure", "microsoft-iis", "front door",
                     "azurewebsites", "cloudapp.azure"],
    "digitalocean": ["digitalocean", "do-"],
    "alibaba":      ["alibaba", "aliyun"],
    "oracle":       ["oracle cloud", "oci", "oraclecloud"],
    "cloudflare":   ["cloudflare"],
    "fastly":       ["fastly"],
}

DBMS_SIGNATURES = {
    "mysql":      ["mysql", "mariadb", "phpmyadmin"],
    "postgresql": ["postgresql", "postgres", "pgsql"],
    "mssql":      ["mssql", "sql server", "asp.net", "iis"],
    "oracle":     ["oracle database", "oracle db", "oracle http server"],
    "sqlite":     ["sqlite"],
    "mongodb":    ["mongodb", "mongoose"],
}


def _to_text(x):
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return " ".join(f"{k}: {v}" for k, v in x.items())
    if isinstance(x, (list, tuple, set)):
        return " ".join(_to_text(i) for i in x)
    return str(x)


def _match_signatures(haystack, signatures):
    hits = set()
    low = (haystack or "").lower()
    for key, needles in signatures.items():
        for needle in needles:
            if needle in low:
                hits.add(key)
                break
    return hits


def detect_waf(x):
    h = _match_signatures(_to_text(x), WAF_SIGNATURES)
    return next(iter(h)) if h else None


def detect_provider(x):
    h = _match_signatures(_to_text(x), CLOUD_SIGNATURES)
    return next(iter(h)) if h else None


def detect_dbms(x):
    h = _match_signatures(_to_text(x), DBMS_SIGNATURES)
    return next(iter(h)) if h else None


# =============================================================================
#  FORMATTERS
# =============================================================================
def format_bytes(n):
    try:
        n = float(n)
    except Exception:
        return str(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def format_duration(seconds):
    try:
        s = float(seconds)
    except Exception:
        return str(seconds)
    if s < 1:
        return f"{s * 1000:.0f}ms"
    if s < 60:
        return f"{s:.1f}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{int(m)}m {int(s)}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h {int(m)}m"


# =============================================================================
#  DOCTOR  — full application health report
# =============================================================================
def _status_icon(ok, warn=False):
    if ok:
        return f"{C.GR}✓{C.R}"
    if warn:
        return f"{C.YE}!{C.R}"
    return f"{C.RE}✗{C.R}"


def doctor():
    """Print a comprehensive health report of the TRIDENT installation."""
    banner()
    section("TRIDENT :: System Health Report")

    # ---------- Core paths ----------
    print(f"{C.B}Working directory:{C.R}  {Path.cwd()}")
    print(f"{C.B}TRIDENT root:     {C.R}  {ROOT}")
    print()

    # ---------- Python + deps ----------
    print(f"{C.B}Python:{C.R}  {platform.python_version()} ({platform.platform()})")
    print()

    print(f"{C.B}Dependencies:{C.R}")
    deps = [
        ("requests",   _HAVE_REQUESTS, False, "pip install requests"),
        ("pyyaml",     _yaml is not None, False, "pip install pyyaml"),
        ("beautifulsoup4", _has_module("bs4"), False, "pip install beautifulsoup4"),
        ("psutil",     _psutil is not None, True, "pip install psutil (recommended)"),
        ("playwright", _has_module("playwright"), True, "pip install playwright"),
        ("lxml",       _has_module("lxml"), True, "pip install lxml"),
    ]
    for name, present, optional, hint in deps:
        icon = _status_icon(present, warn=optional and not present)
        note = "" if present else f"  {C.GY}→ {hint}{C.R}"
        opt = f" {C.GY}(optional){C.R}" if optional else ""
        print(f"  {icon} {name:<16}{opt}{note}")
    print()

    # ---------- System resources ----------
    info = collect_system_info()
    section("System Resources")
    print(f"  Hostname:      {info.get('hostname','?')}")
    print(f"  CPU cores:     {info.get('cpu_count', 0)}")
    if info.get("load_avg"):
        print(f"  Load avg:      {info['load_avg']}")
    if info.get("mem_total"):
        print(f"  Memory:        "
              f"{format_bytes(info['mem_available'])} free / "
              f"{format_bytes(info['mem_total'])} total "
              f"({info.get('mem_percent', 0)}% used)")
    if info.get("disk_total"):
        print(f"  Disk (cwd):    "
              f"{format_bytes(info['disk_free'])} free / "
              f"{format_bytes(info['disk_total'])} total "
              f"({info.get('disk_percent', 0)}% used)")
    if info.get("uptime_sec"):
        print(f"  Uptime:        {format_duration(info['uptime_sec'])}")
    lvl, msg = resource_verdict(info)
    icon = _status_icon(lvl == "ok", warn=(lvl == "warn"))
    print(f"\n  {icon} {msg}")

    # ---------- Payload vault ----------
    section("Payload Vault")
    status = vault_status(PAYLOAD_DIR)
    if not status:
        print(f"  {C.RE}✗{C.R} no payloads found in {PAYLOAD_DIR}")
    else:
        print(f"  {C.B}{'NAME':<24} {'YAML':<6} {'B64':<6} {'XOR':<6}{C.R}")
        print(f"  {'-'*48}")
        for name in sorted(status):
            s = status[name]
            y = f"{C.GR}✓{C.R}" if s["yaml"] else f"{C.GY}-{C.R}"
            b = f"{C.GR}✓{C.R}" if s["b64"]  else f"{C.GY}-{C.R}"
            x = f"{C.GR}✓{C.R}" if s["xor"]  else f"{C.GY}-{C.R}"
            print(f"  {name:<24} {y:<14} {b:<14} {x:<14}")
        total = len(status)
        encoded = sum(1 for s in status.values() if s["b64"] or s["xor"])
        print(f"\n  {encoded}/{total} payloads encoded "
              f"({C.GY}run `trident-utils encode` to encode the rest{C.R})")

    # ---------- Response vault ----------
    section("Response Vault")
    rstatus = vault_status(RESPONSE_DIR)
    if not rstatus:
        print(f"  {C.YE}!{C.R} no responses found in {RESPONSE_DIR}")
    else:
        encoded = sum(1 for s in rstatus.values() if s["b64"] or s["xor"])
        print(f"  {len(rstatus)} response set(s), {encoded} encoded")

    # ---------- .env + API keys ----------
    section(".env & AI Providers")
    env_path = find_env_file()
    if env_path:
        print(f"  {_status_icon(True)} .env found: {env_path}")
    else:
        print(f"  {_status_icon(False, warn=True)} no .env file — "
              f"copy `env_example` to `.env` and add your keys")

    env = load_env()
    rows = provider_summary(env)
    print()
    print(f"  {C.B}{'PROVIDER':<16} {'STATUS':<10} {'ENV VAR':<24} "
          f"{'PRICING':<10}{C.R}")
    print(f"  {'-'*72}")
    usable_count = 0
    for r in rows:
        if r["usable"]:
            usable_count += 1
            icon = f"{C.GR}✓ ready{C.R}"
        else:
            icon = f"{C.GY}·  --{C.R}"
        var = r["env_var"] or f"{C.GY}not set{C.R}"
        print(f"  {r['label']:<16} {icon:<22} {var:<24} {r['pricing']}")
    print()
    print(f"  {C.B}{usable_count}{C.R} provider(s) usable right now.")

    best = pick_provider()
    if best:
        print(f"  Auto-select chain head: {C.GR}{best}{C.R} "
              f"({AI_PROVIDERS[best]['label']})")
    else:
        print(f"  {C.YE}!{C.R} no AI provider configured — "
              f"triage will run in signature-only mode.")

    # ---------- Headers ----------
    section("Header Profiles")
    jar = HeaderJar(HELPER_DIR / "headers")
    jar.load()
    profiles = jar.profiles_loaded()
    if not profiles:
        print(f"  {C.GY}(no header profiles — directory "
              f"{HELPER_DIR / 'headers'} is empty or missing){C.R}")
    else:
        for name, count in profiles:
            print(f"  {C.GR}✓{C.R} {name:<28} {count} headers")

    # ---------- Helper configs ----------
    section("Helper Configs")
    for fname in ("proxies.yaml", "user_agents.yaml"):
        p = HELPER_DIR / fname
        if p.exists():
            print(f"  {_status_icon(True)} {fname}")
        else:
            print(f"  {_status_icon(False, warn=True)} {fname} "
                  f"{C.GY}(optional){C.R}")

    # ---------- Writability ----------
    section("Writability")
    for label, d in [("output/", OUTPUT_DIR), ("reports/", REPORT_DIR)]:
        d = Path(d)
        try:
            d.mkdir(parents=True, exist_ok=True)
            test = d / f".trident_write_test_{os.getpid()}"
            test.write_text("ok")
            test.unlink()
            print(f"  {_status_icon(True)} {label} writable")
        except Exception as e:
            print(f"  {_status_icon(False)} {label} NOT writable: {e}")

    # ---------- Verdict ----------
    section("Verdict")
    checks = [
        _HAVE_REQUESTS, _yaml is not None, env_path is not None,
        usable_count > 0, len(profiles) > 0 or True,  # headers optional
        sum(1 for s in status.values() if s["b64"] or s["xor"]) > 0,
    ]
    passed = sum(1 for c in checks if c)
    total_c = len(checks)
    pct = int(100 * passed / total_c)

    if pct >= 80:
        print(f"  {C.GR}{C.B}READY TO LAUNCH{C.R}  ({passed}/{total_c} checks passed)")
        print(f"  {C.GY}Run: python cli.py --help{C.R}")
    elif pct >= 50:
        print(f"  {C.YE}{C.B}PARTIALLY READY{C.R}  ({passed}/{total_c} checks passed)")
        print(f"  {C.GY}Fix the warnings above before scanning.{C.R}")
    else:
        print(f"  {C.RE}{C.B}NOT READY{C.R}  ({passed}/{total_c} checks passed)")
        print(f"  {C.GY}Address the failures above, then re-run `doctor`.") 
    print()
    return 0


def _has_module(name):
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


# =============================================================================
#  SELF-TEST
# =============================================================================
def _self_test():
    # --- basics ---
    assert safe_filename("a/b\\c?d") == "a_b_c_d"
    assert parse_json_path("$.a.b[0].c") == ["a", "b", 0, "c"]
    obj = {"a": {"b": [{"c": 1}]}}
    set_json_path(obj, "$.a.b[0].c", 99)
    assert obj["a"]["b"][0]["c"] == 99
    assert detect_waf("cloudflare-nginx") == "cloudflare"
    assert detect_provider("Amazon S3") == "aws"
    assert detect_dbms("PostgreSQL 15") == "postgresql"
    assert url_extension("http://x/y/z.js?v=1") == ".js"

    # --- env parser ---
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".env",
                                     delete=False) as f:
        f.write(
            "# comment\n"
            "DEEPSEEK_API_KEY=sk-abc123\n"
            "GROQ_API_KEY=\"sk-quoted-123\"\n"
            "export GEMINI_API_KEY='sk-single'\n"
            "EMPTY_KEY=\n"
            "   \n"
            "WITH_HASH=value # trailing\n"
        )
        env_path = f.name
    parsed = parse_env_file(env_path)
    assert parsed["DEEPSEEK_API_KEY"] == "sk-abc123"
    assert parsed["GROQ_API_KEY"] == "sk-quoted-123"
    assert parsed["GEMINI_API_KEY"] == "sk-single"
    assert parsed["EMPTY_KEY"] == ""
    assert parsed["WITH_HASH"] == "value"
    Path(env_path).unlink()

    # --- header parsing ---
    s1 = "Cookie: a=b\nX-Custom: hello\n"
    p1 = parse_header_block(s1)
    assert p1.get("Cookie") == "a=b"

    s2 = "GET /path HTTP/1.1\r\nHost: y\r\nCookie: z\r\n"
    p2 = parse_header_block(s2)
    assert p2.get("Cookie") == "z"
    assert not any(k.startswith("GET") for k in p2)

    s3 = "POST /api/v1/events HTTP/2\nHost: apis.example.com\nCookie: c=d\n"
    p3 = parse_header_block(s3)
    assert p3.get("Cookie") == "c=d"
    assert not any(k.startswith("POST") for k in p3)

    s4 = "X-Multi: part1\n part2\n part3\n"
    p4 = parse_header_block(s4)
    assert p4.get("X-Multi") == "part1 part2 part3"

    s5 = ":method: POST\n:path: /x\nCookie: a=b\n"
    p5 = parse_header_block(s5)
    assert p5.get("Cookie") == "a=b"
    assert not any(k.startswith(":") for k in p5)

    # hop-by-hop
    stripped = strip_hop_by_hop({
        "Content-Length": "100",
        "Content-Encoding": "gzip",
        "Host": "y",
        "Cookie": "z",
    })
    assert "Content-Length" not in stripped
    assert "Host" not in stripped
    assert "Cookie" in stripped

    # masking
    assert mask_header_value("Cookie", "session=abc12345678").startswith("sess")
    assert mask_header_value("Authorization", "short") == "***"

    # --- XOR round trip ---
    original = b"UNION SELECT 1,2,3 -- payload with 'quotes' and \"double\""
    x = _xor_bytes(original, _XOR_KEY)
    back = _xor_bytes(x, _XOR_KEY)
    assert back == original

    # --- vault round-trip ---
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        src = tdir / "test.yaml"
        src.write_text("name: sqli\npayloads:\n  - \"' OR 1=1 --\"\n")

        # b64
        out_b64, _, _ = encode_payload_file(src, mode="b64")
        assert out_b64.exists()
        decoded_text = _read_payload_bytes(out_b64)
        assert "' OR 1=1 --" in decoded_text

        # xor
        out_xor, _, _ = encode_payload_file(src, mode="xor")
        assert out_xor.exists()
        decoded_text2 = _read_payload_bytes(out_xor)
        assert "' OR 1=1 --" in decoded_text2

    return True


# =============================================================================
#  CLI COMMANDS
# =============================================================================
def _cli_encode(args):
    mode = "xor" if args.xor else "b64"
    keep = not args.remove_source
    n, errs = vault_encode_all(mode=mode, keep_source=keep)
    log(f"encoded {n} file(s) using {mode} mode", "ok", "VAULT")
    for e in errs:
        log(e, "err", "VAULT")
    return 0 if not errs else 1


def _cli_decode(args):
    n, errs = vault_decode_all()
    log(f"decoded {n} file(s)", "ok", "VAULT")
    for e in errs:
        log(e, "err", "VAULT")
    return 0 if not errs else 1


def _cli_vault_status(_args):
    banner()
    section("TRIDENT :: Payload Vault Status")
    status = vault_status(PAYLOAD_DIR)
    if not status:
        log(f"no payloads found in {PAYLOAD_DIR}", "warn")
        return 1
    print(f"  {C.B}{'NAME':<24} {'YAML':<6} {'B64':<6} {'XOR':<6}{C.R}")
    print(f"  {'-'*48}")
    for name in sorted(status):
        s = status[name]
        y = f"{C.GR}yes{C.R}" if s["yaml"] else f"{C.GY}-{C.R}  "
        b = f"{C.GR}yes{C.R}" if s["b64"]  else f"{C.GY}-{C.R}  "
        x = f"{C.GR}yes{C.R}" if s["xor"]  else f"{C.GY}-{C.R}  "
        print(f"  {name:<24} {y:<14} {b:<14} {x:<14}")
    print()
    return 0


def _cli_keys(args):
    banner()
    section("TRIDENT :: AI Provider Keys")
    env_path = find_env_file()
    if env_path:
        print(f"  {C.GR}✓{C.R} .env loaded from {env_path}\n")
    else:
        print(f"  {C.YE}!{C.R} no .env found — checking os.environ only\n")

    env = load_env()
    rows = provider_summary(env)
    print(f"  {C.B}{'PROVIDER':<16} {'STATUS':<12} {'ENV VAR':<24} "
          f"{'PRICING':<10}{C.R}")
    print(f"  {'-'*76}")

    usable = []
    for r in rows:
        if r["usable"]:
            usable.append(r["provider"])
            status = f"{C.GR}✓ ready{C.R}"
        else:
            status = f"{C.GY}·  missing{C.R}"
        var = r["env_var"] or f"{C.GY}--{C.R}"
        print(f"  {r['label']:<16} {status:<22} {var:<24} {r['pricing']}")

    print()
    print(f"  {C.B}{len(usable)}/{len(rows)}{C.R} providers usable.")

    if args.probe and usable:
        print()
        section("Probing providers (lightweight reachability)")
        for name in usable:
            ok, msg = probe_provider(name)
            icon = f"{C.GR}✓{C.R}" if ok else f"{C.RE}✗{C.R}"
            print(f"  {icon} {AI_PROVIDERS[name]['label']:<18} {msg}")

    best = pick_provider()
    if best:
        print(f"\n  Auto-select head: {C.GR}{best}{C.R}")
    return 0 if usable else 1


def _cli_sysinfo(_args):
    banner()
    section("TRIDENT :: System Resources")
    info = collect_system_info()
    for k, v in info.items():
        if k in ("mem_total", "mem_available", "disk_total", "disk_free",
                 "swap_total"):
            v = format_bytes(v)
        if k == "uptime_sec":
            v = format_duration(v)
        print(f"  {k:<16} {v}")
    lvl, msg = resource_verdict(info)
    print()
    icon = _status_icon(lvl == "ok", warn=(lvl == "warn"))
    print(f"  {icon} {msg}")
    return 0


def _cli_headers(args):
    hdir = Path(args.headers_dir)
    if not hdir.exists():
        log(f"directory not found: {hdir}", "err")
        return 1
    jar = HeaderJar(hdir)
    jar.load()
    profiles = jar.profiles_loaded()
    if not profiles:
        log(f"no profiles found in {hdir}", "warn")
        return 1

    banner()
    section("TRIDENT :: Header Profiles")
    for name, count in profiles:
        print(f"  {C.GR}✓{C.R} {name:<28} {count} headers")

    if args.test:
        print()
        section(f"Resolved headers for {args.test}")
        merged = jar.headers_for(args.test)
        if not merged:
            print("  (no headers)")
        for k in sorted(merged):
            print(f"  {k}: {mask_header_value(k, merged[k])}")
    return 0


def _cli_self_test(_args):
    banner()
    section("TRIDENT :: Self-Test")
    try:
        if _self_test():
            print(f"  {C.GR}✓{C.R} All assertions passed "
                  f"(trident_utils v{VERSION})")
            return 0
    except AssertionError:
        import traceback
        traceback.print_exc()
        print(f"  {C.RE}✗{C.R} Self-test FAILED")
        return 1
    return 1


def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        prog="trident-utils",
        description=f"TRIDENT shared utilities (v{VERSION})",
    )
    sub = ap.add_subparsers(dest="cmd")

    p_enc = sub.add_parser("encode", help="Encode payloads/ *.yaml -> *.b64 or *.xor")
    p_enc.add_argument("--xor", action="store_true",
                       help="XOR + base64 (harder for AV to fingerprint)")
    p_enc.add_argument("--remove-source", action="store_true",
                       help="Delete the original .yaml after encoding")

    sub.add_parser("decode", help="Decode *.b64/*.xor -> *.yaml")
    sub.add_parser("vault-status", help="Show which payloads are encoded")
    sub.add_parser("self-test", help="Run internal sanity checks")
    sub.add_parser("doctor", help="Full application health report")
    sub.add_parser("sysinfo", help="System resource snapshot")

    p_keys = sub.add_parser("keys", help="Show which AI providers are usable")
    p_keys.add_argument("--probe", action="store_true",
                        help="Lightweight reachability probe of usable providers")

    p_hdr = sub.add_parser("headers", help="Inspect header profiles")
    p_hdr.add_argument("headers_dir",
                       help="directory containing default.txt + host.txt")
    p_hdr.add_argument("--test", default=None,
                       help="resolve headers for this host and print (masked)")

    args = ap.parse_args()

    if args.cmd == "encode":       return _cli_encode(args)
    if args.cmd == "decode":       return _cli_decode(args)
    if args.cmd == "vault-status": return _cli_vault_status(args)
    if args.cmd == "keys":         return _cli_keys(args)
    if args.cmd == "sysinfo":      return _cli_sysinfo(args)
    if args.cmd == "headers":      return _cli_headers(args)
    if args.cmd == "self-test":    return _cli_self_test(args)
    if args.cmd == "doctor":       return doctor()

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(_cli())
