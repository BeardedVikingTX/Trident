#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TRIDENT :: burp_to_sites.py — v2.0.0
#  Import Burp Suite URL dumps into the TRIDENT workspace format.
# -----------------------------------------------------------------------------
#  Design goals:
#    · FAST      — 40 workers, no throttle by default, 3s connect timeout
#    · RELIABLE  — every URL gets a .json, even on catastrophic failure
#    · SAFE      — write to disk BEFORE any AI call
#    · OPTIONAL  — AI is a second pass, never blocks the fetch
#    · FAMILIAR  — same output shape as HUGINN's v3.1 importer
#
#  Output format (per URL):
#      workspace/sites/<host>/<slug>.json
#      {
#        "url": ..., "status": ..., "method": ..., "content_type": ...,
#        "content_length": ..., "title": ..., "params": [...],
#        "headers": {...}, "cookies": {...}, "content": "...",
#        "_source": "burp", "_fetched_at": "...",
#        "_fetch": {"authenticated": bool, "header_names": [...], "timestamp": ...},
#        "_ai":    {"enabled": bool, "ok": bool, ...}     # always present
#        "ai_recon": {...}                                 # if AI ran
#      }
#
#  Circuit breaker: hosts failing HOST_DEAD_AFTER times in a row are
#  skipped for the rest of the run. Kills the "1h27m ETA" problem.
# =============================================================================

import argparse
import hashlib
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

from trident_utils import (
    VERSION as TRIDENT_VERSION,
    log, section, save_json, load_json, send_request,
    safe_filename, format_duration, now_iso,
    AI_PROVIDERS, PROVIDER_CHAIN,
    resolve_api_keys, usable_providers, pick_provider, provider_summary,
    load_env, find_env_file,
    HeaderJar, mask_header_value,
    C, _HAVE_REQUESTS,
)

if not _HAVE_REQUESTS:
    print("[!] requests is required. pip install requests")
    sys.exit(1)


# =============================================================================
#  PRESETS
# =============================================================================
PRESETS = {
    "bugbounty": {
        "description": "Balanced — skips CDNs, static assets, third-party hosts",
        "exclude_host": (
            r"(rbxcdn|akamai|cloudfront|cloudflare|fastly|"
            r"cdn\.|\.cdn\.|static\.|assets\.|img\.|images\.|fonts\.|"
            r"analytics\.|tracking\.|telemetry\.|beacon\.|"
            r"\.googleapis\.com|\.gstatic\.com|\.jsdelivr\.net|"
            r"\.cloudflare\.com|\.newrelic\.com|\.datadoghq\.com|"
            r"\.sentry\.io|\.segment\.(io|com)|\.mixpanel\.com)"
        ),
        "exclude_path": (
            r"\.(js|mjs|css|map|png|jpg|jpeg|gif|svg|webp|ico|"
            r"woff|woff2|ttf|otf|eot|mp4|webm|mp3|wav|ogg|"
            r"pdf|zip|tar|gz|7z|rar|exe|dll|bin)$"
        ),
    },
    "strict": {
        "description": "Paranoid — only API-like endpoints",
        "include_path": (
            r"/(api|v[0-9]+|graphql|rest|oauth|auth|admin|"
            r"user|account|billing|payment|login|session)"
        ),
        "exclude_path": (
            r"\.(js|mjs|css|map|png|jpg|jpeg|gif|svg|webp|ico|"
            r"woff|woff2|ttf|otf|eot)$"
        ),
    },
    "api-only": {
        "description": "Only /api/ /v1/ /graphql paths",
        "include_path": r"/(api|v[0-9]+|graphql|rest)/",
    },
    "none": {
        "description": "No automatic filtering — raw import",
    },
}

STATIC_EXTENSIONS = re.compile(
    r"\.(js|mjs|css|map|png|jpg|jpeg|gif|svg|webp|ico|bmp|"
    r"woff|woff2|ttf|otf|eot|mp4|webm|mp3|wav|ogg|ogv|"
    r"pdf|zip|tar|gz|7z|rar|exe|dll|so|bin)$",
    re.I,
)

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_reader", "utm_vis", "utm_user",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "mc_eid", "mc_cid",
    "_ga", "_gl", "yclid", "igshid", "twclid", "ttclid",
    "ref", "referrer", "source",
    "cache_buster", "_", "cb", "ts", "timestamp", "_t", "_ts",
}


# =============================================================================
#  CONFIG
# =============================================================================
MAX_BODY_BYTES      = 500_000
FETCH_TIMEOUT       = 10         # read timeout
CONNECT_TIMEOUT     = 3          # TCP connect timeout
DEFAULT_DELAY       = 0.0        # no throttle by default
DEFAULT_WORKERS     = 20
DEFAULT_AI_WORKERS  = 2
DEFAULT_AI_TIMEOUT  = 30
PROGRESS_EVERY      = 25
HOST_DEAD_AFTER     = 5          # consecutive failures → skip host
HOST_DEAD_COOLDOWN  = 120        # seconds before retrying a dead host

AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token",
    "proxy-authorization", "x-amz-security-token", "x-goog-api-key",
}


# =============================================================================
#  AI CLIENT — multi-provider, auto-detects from .env
# =============================================================================
class AIClient:
    """Self-contained chat client. Picks provider via trident_utils.pick_provider()."""

    def __init__(self, prefer=None, timeout=DEFAULT_AI_TIMEOUT, max_tokens=1200):
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.env = load_env()
        self.keys = resolve_api_keys(self.env)
        self.provider = pick_provider(prefer, self.env)
        if self.provider:
            cfg = AI_PROVIDERS[self.provider]
            self.model = cfg["default"]
            self.label = cfg["label"]
            self.key = self.keys[self.provider]
        else:
            self.model = self.label = self.key = None
        self._lock = threading.Lock()
        self.stats = {"calls": 0, "ok": 0, "failed": 0,
                      "tokens_in": 0, "tokens_out": 0}

    def available(self):
        return bool(self.provider and self.key)

    def _bump(self, ok, ti=0, to=0):
        with self._lock:
            self.stats["calls"] += 1
            self.stats["ok" if ok else "failed"] += 1
            self.stats["tokens_in"] += ti
            self.stats["tokens_out"] += to

    def chat(self, system_prompt, user_prompt, json_mode=True):
        if not self.available():
            return None, {}
        p = self.provider
        try:
            if p in ("groq", "deepseek", "openai"):
                return self._openai(system_prompt, user_prompt, json_mode)
            if p == "gemini":
                return self._gemini(system_prompt, user_prompt, json_mode)
            if p == "anthropic":
                return self._anthropic(system_prompt, user_prompt)
            if p == "huggingface":
                return self._hf(system_prompt, user_prompt)
            if p == "ollama":
                return self._ollama(system_prompt, user_prompt, json_mode)
        except Exception as e:
            log(f"AI call failed ({p}): {type(e).__name__}: {e}", "warn", "AI")
            self._bump(False)
            return None, {}
        return None, {}

    def _openai(self, sp, up, jm):
        cfg = AI_PROVIDERS[self.provider]
        url = cfg["base_url"].rstrip("/") + "/chat/completions"
        body = {"model": self.model,
                "messages": [{"role": "system", "content": sp},
                             {"role": "user", "content": up}],
                "max_tokens": self.max_tokens, "temperature": 0.15}
        if jm:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.key}",
                   "Content-Type": "application/json"}
        r = send_request(url, method="POST", headers=headers, json_body=body,
                         timeout=self.timeout, retry=False)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        u = data.get("usage", {}) or {}
        self._bump(True, u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
        return text, u

    def _gemini(self, sp, up, jm):
        url = (f"{AI_PROVIDERS['gemini']['base_url']}/models/{self.model}"
               f":generateContent?key={self.key}")
        body = {"contents": [{"role": "user", "parts": [{"text": sp + "\n\n" + up}]}],
                "generationConfig": {"temperature": 0.15,
                                      "maxOutputTokens": self.max_tokens}}
        if jm:
            body["generationConfig"]["responseMimeType"] = "application/json"
        r = send_request(url, method="POST", json_body=body,
                         timeout=self.timeout, retry=False)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            text = ""
        u = data.get("usageMetadata", {}) or {}
        self._bump(True, u.get("promptTokenCount", 0), u.get("candidatesTokenCount", 0))
        return text, u

    def _anthropic(self, sp, up):
        url = AI_PROVIDERS["anthropic"]["base_url"].rstrip("/") + "/messages"
        headers = {"x-api-key": self.key, "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        body = {"model": self.model, "max_tokens": self.max_tokens,
                "system": sp, "messages": [{"role": "user", "content": up}]}
        r = send_request(url, method="POST", headers=headers, json_body=body,
                         timeout=self.timeout, retry=False)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        u = data.get("usage", {}) or {}
        self._bump(True, u.get("input_tokens", 0), u.get("output_tokens", 0))
        return text, u

    def _hf(self, sp, up):
        url = f"{AI_PROVIDERS['huggingface']['base_url'].rstrip('/')}/models/{self.model}"
        headers = {"Authorization": f"Bearer {self.key}"}
        body = {"inputs": sp + "\n\n" + up,
                "parameters": {"max_new_tokens": self.max_tokens,
                                "temperature": 0.15, "return_full_text": False}}
        r = send_request(url, method="POST", headers=headers, json_body=body,
                         timeout=self.timeout, retry=False)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        try:
            data = r.json()
            text = data[0].get("generated_text", "") if isinstance(data, list) and data else str(data)
        except Exception:
            text = ""
        self._bump(True)
        return text, {}

    def _ollama(self, sp, up, jm):
        url = AI_PROVIDERS["ollama"]["base_url"].rstrip("/") + "/api/chat"
        body = {"model": self.model,
                "messages": [{"role": "system", "content": sp},
                             {"role": "user", "content": up}],
                "stream": False, "options": {"temperature": 0.15}}
        if jm:
            body["format"] = "json"
        r = send_request(url, method="POST", json_body=body,
                         timeout=self.timeout, retry=False)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        text = (data.get("message") or {}).get("content", "")
        self._bump(True, data.get("prompt_eval_count", 0), data.get("eval_count", 0))
        return text, {}

    def recon_page(self, page):
        if not self.available():
            return None
        body = (page.get("content") or "")[:6000]
        url = page.get("url", "")
        status = page.get("status", 0)
        ctype = page.get("content_type", "")
        params = page.get("params", [])
        title = page.get("title", "")
        headers_safe = {k: mask_header_value(k, v)
                        for k, v in (page.get("headers") or {}).items()
                        if k.lower() in ("server", "x-powered-by", "content-type",
                                         "x-frame-options", "strict-transport-security",
                                         "content-security-policy", "x-csrf-token")}

        system = ("You are a bug bounty reconnaissance analyst. Output "
                  "STRICT JSON describing the page's attack surface. No prose.")
        user = f"""Analyze this HTTP page for bug bounty recon.

URL: {url}
Status: {status}
Content-Type: {ctype}
Title: {title}
URL params: {params}
Notable headers: {json.dumps(headers_safe)}

Body (first 6KB):
\"\"\"
{body}
\"\"\"

Return ONLY this JSON:
{{
  "kind": "api|form|auth|admin|static|error|landing|other",
  "priority": "high|medium|low",
  "interesting": true or false,
  "confidence": 0.0 to 1.0,
  "attack_surface": ["url_params","forms","json_body","cookies","headers","graphql","file_upload"],
  "suggested_scanners": ["sqli","xss","ssrf","open_redirect","path_traversal"],
  "notes": "one short sentence"
}}
"""
        text, usage = self.chat(system, user, json_mode=True)
        if not text:
            return None
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            recon = json.loads(cleaned)
        except Exception:
            m = re.search(r"\{.*\}", cleaned, re.S)
            if not m:
                return None
            try:
                recon = json.loads(m.group(0))
            except Exception:
                return None
        recon.setdefault("kind", "other")
        recon.setdefault("priority", "medium")
        recon.setdefault("interesting", False)
        recon.setdefault("confidence", 0.5)
        recon.setdefault("attack_surface", [])
        recon.setdefault("suggested_scanners", [])
        recon.setdefault("notes", "")
        recon["_usage"] = usage
        return recon


# =============================================================================
#  URL NORMALIZATION
# =============================================================================
def normalize_url(url):
    try:
        p = urlparse(url)
    except Exception:
        return None
    p = p._replace(fragment="")
    if p.query:
        qs = parse_qs(p.query, keep_blank_values=True)
        cleaned = {k: v for k, v in qs.items() if k.lower() not in TRACKING_PARAMS}
        p = p._replace(query=urlencode(cleaned, doseq=True) if cleaned else "")
    return urlunparse(p)


def parse_url_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("GET ", "POST ", "PUT ", "DELETE ",
                        "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ")):
        parts = line.split(" ", 2)
        line = parts[1] if len(parts) >= 2 else None
        if not line:
            return None
    if not line.startswith(("http://", "https://")):
        if "." in line.split("/")[0]:
            line = "https://" + line
        else:
            return None
    return line


def load_urls(path, filter_pattern=None, include_host=None,
              exclude_host=None, include_path=None, exclude_path=None):
    urls, seen = [], set()
    rx_f  = re.compile(filter_pattern) if filter_pattern else None
    rx_ih = re.compile(include_host)   if include_host   else None
    rx_eh = re.compile(exclude_host)   if exclude_host   else None
    rx_ip = re.compile(include_path)   if include_path   else None
    rx_ep = re.compile(exclude_path)   if exclude_path   else None

    stats = {"read": 0, "invalid": 0, "filtered_url": 0,
             "filtered_host": 0, "filtered_path": 0, "dupes": 0, "kept": 0}

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            stats["read"] += 1
            line = parse_url_line(raw)
            if not line:
                stats["invalid"] += 1; continue
            line = normalize_url(line)
            if not line:
                stats["invalid"] += 1; continue
            if rx_f and not rx_f.search(line):
                stats["filtered_url"] += 1; continue
            try:
                parsed = urlparse(line)
            except Exception:
                stats["invalid"] += 1; continue
            host = parsed.netloc.lower()
            path_l = parsed.path.lower()
            if rx_ih and not rx_ih.search(host):
                stats["filtered_host"] += 1; continue
            if rx_eh and rx_eh.search(host):
                stats["filtered_host"] += 1; continue
            if rx_ip and not rx_ip.search(path_l):
                stats["filtered_path"] += 1; continue
            if rx_ep and rx_ep.search(path_l):
                stats["filtered_path"] += 1; continue
            if line in seen:
                stats["dupes"] += 1; continue
            seen.add(line)
            urls.append(line)
            stats["kept"] += 1
    return urls, stats


# =============================================================================
#  SLUG + STATIC DETECTION
# =============================================================================
def slug_for_url(url):
    parsed = urlparse(url)
    path_part = parsed.path.strip("/").replace("/", "_") or "index"
    if parsed.query:
        qs_slug = "_".join(f"{k}={v[0]}"
                            for k, v in sorted(parse_qs(parsed.query).items()))
        path_part = f"{path_part}__{qs_slug}"
    slug = safe_filename(path_part)
    if slug.startswith("_"):
        slug = "p" + slug
    if len(slug) > 180:
        slug = slug[:170] + "_" + hashlib.md5(url.encode()).hexdigest()[:6]
    return slug


def is_static_url(url):
    try:
        p = urlparse(url)
    except Exception:
        return False
    if STATIC_EXTENSIONS.search(p.path):
        return True
    host = p.netloc.lower()
    return any(m in host for m in ("cdn.", ".cdn.", "static.", "assets.",
                                    "img.", "images.", "fonts.", "jsdelivr",
                                    "gstatic", "googleapis"))


# =============================================================================
#  HTTP
# =============================================================================
def _categorize_error(exc_type_name, msg):
    m = (msg or "").lower()
    if "timeout" in m or "timed out" in m: return "timeout"
    if "name or service not known" in m or "getaddrinfo" in m: return "dns"
    if "ssl" in m or "certificate" in m: return "tls"
    if "connection refused" in m: return "refused"
    if "connection reset" in m: return "reset"
    return f"exception:{exc_type_name}"


def describe_fetch_headers(merged):
    if not merged:
        return False, []
    names = sorted(merged.keys())
    authed = any(n.lower() in AUTH_HEADER_NAMES for n in names)
    return authed, names


def fetch_page(url, timeout=FETCH_TIMEOUT, extra_headers=None):
    """Fetch a URL. Retry is OFF — dead hosts fail fast."""
    try:
        r = send_request(url, timeout=(CONNECT_TIMEOUT, timeout),
                         allow_redirects=True, headers=extra_headers,
                         retry=False)
    except Exception as e:
        return None, _categorize_error(type(e).__name__, str(e))
    if r is None:
        return None, "no_response"

    try:
        body = r.text or ""
    except Exception:
        body = ""
    if len(body) > MAX_BODY_BYTES:
        body = body[:MAX_BODY_BYTES]

    cookies = {}
    sc = r.headers.get("Set-Cookie") or r.headers.get("set-cookie") or ""
    if sc:
        for chunk in sc.split(","):
            m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
            if m:
                cookies[m.group(1).strip()] = m.group(2).strip()

    title = ""
    mt = re.search(r"<title[^>]*>([^<]{1,300})</title>", body, re.I)
    if mt:
        title = mt.group(1).strip()

    parsed = urlparse(url)
    try:
        clen = len(r.content or b"")
    except Exception:
        clen = len(body)

    return {
        "url":            url,
        "status":         r.status_code,
        "method":         "GET",
        "content_type":   r.headers.get("Content-Type", ""),
        "content_length": clen,
        "title":          title,
        "params":         list(parse_qs(parsed.query).keys()),
        "headers":        dict(r.headers),
        "cookies":        cookies,
        "content":        body,
        "_source":        "burp",
        "_fetched_at":    now_iso(),
    }, None


def placeholder_page(url, reason="no_fetch"):
    parsed = urlparse(url)
    return {
        "url": url, "status": 0, "method": "GET",
        "content_type": "", "content_length": 0, "title": "",
        "params": list(parse_qs(parsed.query).keys()),
        "headers": {}, "cookies": {}, "content": "",
        "_source": "burp_placeholder",
        "_note": f"no content captured — {reason}",
        "_fetched_at": now_iso(),
    }


def error_page(url, reason):
    """Build a record even when the fetch catastrophically failed."""
    return {
        "url": url, "status": 0, "method": "GET",
        "content_type": "", "content_length": 0, "title": "",
        "params": list(parse_qs(urlparse(url).query).keys()),
        "headers": {}, "cookies": {}, "content": "",
        "_source": "burp_error",
        "_error": reason,
        "_note": "fetch failed — scanners will test URL params only",
        "_fetched_at": now_iso(),
    }


# =============================================================================
#  THROTTLE  — sleeps OUTSIDE the lock, non-blocking for other hosts
# =============================================================================
class HostThrottle:
    def __init__(self, delay):
        self.delay = delay
        self._last = {}
        self._lock = threading.Lock()

    def wait(self, host):
        if self.delay <= 0 or not host:
            return
        while True:
            with self._lock:
                now = time.time()
                last = self._last.get(host, 0.0)
                w = self.delay - (now - last)
                if w <= 0:
                    self._last[host] = now
                    return
            time.sleep(min(w, 0.25))


# =============================================================================
#  CIRCUIT BREAKER  — skip dead hosts entirely
# =============================================================================
class HostCircuitBreaker:
    def __init__(self, limit=HOST_DEAD_AFTER, cooldown=HOST_DEAD_COOLDOWN):
        self.limit = limit
        self.cooldown = cooldown
        self._fail = {}
        self._dead_at = {}
        self._success = {}
        self._lock = threading.Lock()

    def is_dead(self, host):
        with self._lock:
            if self._fail.get(host, 0) < self.limit:
                return False
            # Cooldown: allow one probe every N seconds
            if time.time() - self._dead_at.get(host, 0) > self.cooldown:
                self._fail[host] = self.limit - 1  # allow one retry
                return False
            return True

    def record(self, host, ok):
        with self._lock:
            if ok:
                self._fail[host] = 0
                self._success[host] = self._success.get(host, 0) + 1
            else:
                self._fail[host] = self._fail.get(host, 0) + 1
                if self._fail[host] >= self.limit:
                    self._dead_at[host] = time.time()

    def dead_hosts(self):
        with self._lock:
            return {h: self._fail[h] for h in self._fail
                    if self._fail[h] >= self.limit}


# =============================================================================
#  STATS
# =============================================================================
class FetchStats:
    def __init__(self, total):
        self.total = total
        self.written = self.failed = self.skipped = self.refreshed = 0
        self.dead_skipped = 0
        self.ai_done = self.ai_failed = self.ai_skipped = 0
        self.ai_interesting = 0
        self.ai_by_kind, self.ai_by_priority, self.ai_scanner_hits = {}, {}, {}
        self.error_reasons = {}
        self.authenticated = self.unauthenticated = 0
        self.started_at = time.time()
        self._lock = threading.Lock()

    def bump(self, field, n=1):
        with self._lock:
            setattr(self, field, getattr(self, field, 0) + n)

    def record_error(self, reason):
        with self._lock:
            self.error_reasons[reason] = self.error_reasons.get(reason, 0) + 1

    def record_auth(self, authed):
        with self._lock:
            if authed: self.authenticated += 1
            else: self.unauthenticated += 1

    def record_ai(self, recon):
        with self._lock:
            self.ai_done += 1
            if recon.get("interesting"): self.ai_interesting += 1
            k = recon.get("kind", "other")
            self.ai_by_kind[k] = self.ai_by_kind.get(k, 0) + 1
            p = recon.get("priority", "medium")
            self.ai_by_priority[p] = self.ai_by_priority.get(p, 0) + 1
            for s in recon.get("suggested_scanners", []):
                self.ai_scanner_hits[s] = self.ai_scanner_hits.get(s, 0) + 1

    def snapshot(self):
        with self._lock:
            return {
                "total": self.total,
                "written": self.written, "failed": self.failed,
                "skipped": self.skipped, "refreshed": self.refreshed,
                "dead_skipped": self.dead_skipped,
                "authenticated": self.authenticated,
                "unauthenticated": self.unauthenticated,
                "ai_done": self.ai_done, "ai_failed": self.ai_failed,
                "ai_skipped": self.ai_skipped,
                "ai_interesting": self.ai_interesting,
                "ai_by_kind": dict(self.ai_by_kind),
                "ai_by_priority": dict(self.ai_by_priority),
                "ai_scanner_hits": dict(self.ai_scanner_hits),
                "error_reasons": dict(self.error_reasons),
                "elapsed_s": round(time.time() - self.started_at, 1),
            }


# =============================================================================
#  WORKER
# =============================================================================
def fetch_worker(url, workspace, used_slugs, used_slugs_lock, throttle,
                 header_jar, fallback_headers, no_fetch, refresh,
                 ai_client, ai_semaphore, ai_force, ai_skip_static,
                 stats, out_lock, quiet, circuit):

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    host_dir = workspace / "sites" / safe_filename(host)
    try:
        host_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        stats.record_error(f"mkdir:{type(e).__name__}")
        return url, 0, "error:mkdir"

    # ---- Circuit breaker: bail fast on dead hosts ---------------------
    if not no_fetch and circuit.is_dead(host):
        stats.bump("dead_skipped")
        return url, 0, "skipped_dead"

    slug = slug_for_url(url)
    with used_slugs_lock:
        host_slugs = used_slugs.setdefault(host, {})
        if slug in host_slugs:
            h = hashlib.md5(url.encode()).hexdigest()[:6]
            slug = f"{slug}_{h}"
        host_slugs[slug] = url

    out_path = host_dir / f"{slug}.json"

    # ---- Resume / cache check -----------------------------------------
    record = None
    if out_path.exists() and not refresh:
        try:
            record = load_json(out_path)
            needs_ai = (ai_client is not None
                        and ai_client.available()
                        and "ai_recon" not in record
                        and not record.get("_error"))
            if not needs_ai:
                stats.bump("skipped")
                return url, record.get("status", 0), "skipped"
        except Exception:
            record = None

    # ---- Fetch (if needed) --------------------------------------------
    outcome = "ok"
    if record is None:
        if header_jar is not None:
            merged_headers = header_jar.headers_for(url)
        else:
            merged_headers = dict(fallback_headers or {})
        authed, header_names = describe_fetch_headers(merged_headers)

        if no_fetch:
            record = placeholder_page(url, reason="no_fetch flag")
            outcome = "placeholder"
        else:
            throttle.wait(host)
            record, err = fetch_page(url, extra_headers=merged_headers)
            if record is None:
                stats.record_error(err or "unknown")
                circuit.record(host, ok=False)
                record = error_page(url, err or "unknown")
                outcome = f"error:{err or 'unknown'}"
            else:
                circuit.record(host, ok=True)
                outcome = "ok"

        record["_fetch"] = {
            "authenticated": authed,
            "header_names":  header_names,
            "timestamp":     now_iso(),
        }
        stats.record_auth(authed)
        if refresh and out_path.exists():
            stats.bump("refreshed")

        # ---- SAVE NOW, before any AI call -----------------------------
        try:
            with out_lock:
                save_json(out_path, record)
            stats.bump("written")
        except Exception as e:
            stats.record_error(f"save:{type(e).__name__}")
            return url, record.get("status", 0), "error:save"

    # ---- AI recon (second pass, safe to fail) -------------------------
    if ai_client is not None and ai_client.available() and ai_semaphore is not None:
        skip_ai = False
        if ai_skip_static and is_static_url(url):
            skip_ai = True
            stats.bump("ai_skipped")
        if not skip_ai and not ai_force and "ai_recon" in record:
            skip_ai = True
            stats.bump("ai_skipped")

        if not skip_ai:
            t0 = time.time()
            recon = None
            ai_ok = False
            try:
                with ai_semaphore:
                    recon = ai_client.recon_page(record)
                ai_ok = recon is not None
            except Exception as e:
                if not quiet:
                    log(f"AI error for {url[:80]}: {type(e).__name__}: {e}",
                        "warn", "AI")
            dur_ms = int((time.time() - t0) * 1000)

            record["_ai"] = {
                "enabled":     True,
                "ok":          ai_ok,
                "provider":    ai_client.provider,
                "model":       ai_client.model,
                "model_label": ai_client.label,
                "duration_ms": dur_ms,
                "timestamp":   now_iso(),
            }
            if ai_ok:
                record["ai_recon"] = recon
                stats.record_ai(recon)
            else:
                stats.bump("ai_failed")

            try:
                with out_lock:
                    save_json(out_path, record)
            except Exception as e:
                stats.record_error(f"save_ai:{type(e).__name__}")
        else:
            if "_ai" not in record:
                record["_ai"] = {
                    "enabled": True,
                    "ok": "ai_recon" in record,
                    "provider": ai_client.provider,
                    "model": ai_client.model,
                    "model_label": ai_client.label,
                    "skipped": True,
                    "timestamp": now_iso(),
                }
                try:
                    with out_lock:
                        save_json(out_path, record)
                except Exception:
                    pass
    else:
        # No AI — stamp the record if it hasn't been already
        if "_ai" not in record:
            record["_ai"] = {
                "enabled": False,
                "reason": "no_provider" if ai_client is None else "disabled",
                "timestamp": now_iso(),
            }
            try:
                with out_lock:
                    save_json(out_path, record)
            except Exception:
                pass

    return url, record.get("status", 0), outcome


# =============================================================================
#  DISPLAY
# =============================================================================
def print_host_stats(urls, top=25):
    hosts = {}
    for u in urls:
        try:
            h = urlparse(u).netloc.lower()
        except Exception:
            continue
        hosts[h] = hosts.get(h, 0) + 1
    sh = sorted(hosts.items(), key=lambda x: -x[1])
    print()
    print(f"{C.B}{C.WH}  {'HOST':<52} {'URLS':>6}{C.R}")
    print(f"{C.D}  {'─' * 60}{C.R}")
    for host, count in sh[:top]:
        h = host[:50] + ".." if len(host) > 52 else host
        print(f"  {h:<52} {count:>6}")
    if len(sh) > top:
        remaining = sum(c for _, c in sh[top:])
        print(f"{C.D}  ... and {len(sh) - top} more hosts ({remaining} URLs){C.R}")
    print(f"{C.D}  {'─' * 60}{C.R}")
    print(f"  {'TOTAL':<52} {len(urls):>6}")
    print()


def print_path_stats(urls, top=15):
    paths = {}
    for u in urls:
        try:
            p = urlparse(u).path
        except Exception:
            continue
        segs = [s for s in p.split("/") if s]
        bucket = "/" + segs[0] if segs else "/"
        paths[bucket] = paths.get(bucket, 0) + 1
    sp = sorted(paths.items(), key=lambda x: -x[1])
    print()
    print(f"{C.B}{C.WH}  {'PATH PREFIX':<52} {'URLS':>6}{C.R}")
    print(f"{C.D}  {'─' * 60}{C.R}")
    for prefix, count in sp[:top]:
        p = prefix[:50] + ".." if len(prefix) > 52 else prefix
        print(f"  {p:<52} {count:>6}")
    print()


def print_ai_summary(stats, ai_client):
    snap = stats.snapshot()
    if not (snap["ai_done"] or snap["ai_failed"] or snap["ai_skipped"]):
        return
    section("AI RECON SUMMARY")
    log(f"provider      : {ai_client.label} / {ai_client.model}", "info", "AI")
    log(f"analyzed      : {snap['ai_done']} pages", "ok", "AI")
    if snap["ai_interesting"]:
        pct = 100.0 * snap["ai_interesting"] / max(1, snap["ai_done"])
        log(f"interesting   : {snap['ai_interesting']} ({pct:.0f}%)", "info", "AI")
    if snap["ai_skipped"]:
        log(f"skipped       : {snap['ai_skipped']} (static or cached)", "info", "AI")
    if snap["ai_failed"]:
        log(f"failed        : {snap['ai_failed']}", "warn", "AI")
    if snap["ai_by_priority"]:
        p = snap["ai_by_priority"]
        log(f"by priority   : high={p.get('high', 0)} "
            f"medium={p.get('medium', 0)} low={p.get('low', 0)}", "info", "AI")
    if snap["ai_scanner_hits"]:
        s = sorted(snap["ai_scanner_hits"].items(), key=lambda x: -x[1])
        log("scanner hints : " + "  ".join(f"{n}={c}" for n, c in s[:8]), "info", "AI")
    st = ai_client.stats
    log(f"usage         : {st['calls']} calls ({st['ok']} ok / {st['failed']} fail) "
        f"tokens {st['tokens_in']}/{st['tokens_out']}", "info", "AI")


def write_ai_index(workspace, results):
    index = {"generated_at": now_iso(), "total": len(results), "pages": []}
    rank = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda r: (
        rank.get(r.get("priority", "low"), 3),
        0 if r.get("interesting") else 1,
        r.get("url", ""),
    ))
    for r in results:
        index["pages"].append({
            "url":                r.get("url", ""),
            "kind":               r.get("kind", ""),
            "priority":           r.get("priority", ""),
            "interesting":        r.get("interesting", False),
            "confidence":         r.get("confidence", 0.0),
            "attack_surface":     r.get("attack_surface", []),
            "suggested_scanners": r.get("suggested_scanners", []),
            "notes":              r.get("notes", ""),
        })
    save_json(workspace / "_ai_recon_index.json", index)
    return len(index["pages"])


# =============================================================================
#  ARGPARSE
# =============================================================================
def build_parser():
    ap = argparse.ArgumentParser(
        description="TRIDENT :: Burp URLs → workspace (fast, reliable, AI-optional)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Presets:
  bugbounty  Skips CDNs, static assets, third-party hosts (DEFAULT)
  strict     Only API-like endpoints
  api-only   Only /api/ /v1/ /graphql paths
  none       No automatic filtering — raw import

AI auto-selection (first usable wins):
  groq → gemini → deepseek → openai → anthropic → huggingface → ollama

Examples:
  python3 burp_to_sites.py urls.txt workspace/
  python3 burp_to_sites.py urls.txt workspace/ --fast
  python3 burp_to_sites.py urls.txt workspace/ --ai
  python3 burp_to_sites.py urls.txt workspace/ --ai --ai-provider groq
  python3 burp_to_sites.py urls.txt workspace/ --no-auth
  python3 burp_to_sites.py urls.txt workspace/ --no-fetch
  python3 burp_to_sites.py urls.txt workspace/ --refresh
  python3 burp_to_sites.py urls.txt workspace/ --dry-run
  python3 burp_to_sites.py urls.txt workspace/ --stats-only
""",
    )
    ap.add_argument("urls_file", help="text file with one URL per line")
    ap.add_argument("workspace", help="workspace directory to create")

    # Filtering
    ap.add_argument("--preset", choices=list(PRESETS.keys()), default="bugbounty")
    ap.add_argument("--filter", default=None)
    ap.add_argument("--include-host", default=None)
    ap.add_argument("--exclude-host", default=None)
    ap.add_argument("--include-path", default=None)
    ap.add_argument("--exclude-path", default=None)
    ap.add_argument("--no-cdn", action="store_true")

    # Behavior
    ap.add_argument("--no-fetch", action="store_true",
                    help="register URLs without fetching (still saves JSON)")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--stats-only", action="store_true")
    ap.add_argument("--fast", action="store_true",
                    help="fast mode: 40 workers, no delay, 6s read timeout, no AI")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--timeout", type=int, default=FETCH_TIMEOUT)
    ap.add_argument("--dead-after", type=int, default=HOST_DEAD_AFTER,
                    help=f"consecutive failures before host is skipped (default {HOST_DEAD_AFTER})")
    ap.add_argument("-q", "--quiet", action="store_true")

    # Auth
    ap.add_argument("--headers-dir", default=None)
    ap.add_argument("--no-auth", action="store_true")
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--header", action="append", default=[])

    # AI
    ap.add_argument("--ai", action="store_true",
                    help="enable AI page reconnaissance")
    ap.add_argument("--ai-provider", default=None)
    ap.add_argument("--ai-workers", type=int, default=DEFAULT_AI_WORKERS)
    ap.add_argument("--ai-timeout", type=int, default=DEFAULT_AI_TIMEOUT)
    ap.add_argument("--ai-force", action="store_true")
    ap.add_argument("--ai-skip-static", action="store_true")

    return ap


def merge_preset_filters(args):
    preset = PRESETS.get(args.preset, {})
    result = {"filter": args.filter, "include_host": args.include_host,
              "exclude_host": args.exclude_host, "include_path": args.include_path,
              "exclude_path": args.exclude_path}
    for key in ("include_host", "exclude_host", "include_path", "exclude_path"):
        if result[key] is None and key in preset:
            result[key] = preset[key]
    if args.no_cdn:
        cdn_rx = (r"(cdn\.|\.cdn\.|akamai|cloudfront|cloudflare|fastly|"
                  r"\.googleapis\.com|\.gstatic\.com|\.jsdelivr\.net)")
        if result["exclude_host"]:
            result["exclude_host"] = f"({result['exclude_host']})|({cdn_rx})"
        else:
            result["exclude_host"] = cdn_rx
    return result


def parse_extra_headers(cookie, header_list):
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    for h in header_list:
        if ":" in h:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    return headers


# =============================================================================
#  MAIN
# =============================================================================
def main():
    ap = build_parser()
    args = ap.parse_args()

    # --fast shortcut
    if args.fast:
        args.workers = 40
        args.delay = 0.0
        args.timeout = 6
        args.ai = False
        log("fast mode: workers=40 delay=0 timeout=6s ai=off", "warn")

    urls_file = Path(args.urls_file)
    if not urls_file.exists():
        log(f"URLs file not found: {urls_file}", "err")
        sys.exit(1)

    workspace = Path(args.workspace)
    preset_info = PRESETS.get(args.preset, {})
    if preset_info.get("description"):
        log(f"preset : {args.preset} — {preset_info['description']}", "info")

    filters = merge_preset_filters(args)

    # ---- Load & filter --------------------------------------------------
    section("LOADING & FILTERING")
    try:
        urls, stats_load = load_urls(
            urls_file,
            filter_pattern=filters["filter"],
            include_host=filters["include_host"],
            exclude_host=filters["exclude_host"],
            include_path=filters["include_path"],
            exclude_path=filters["exclude_path"],
        )
    except Exception as e:
        log(f"failed to load URLs: {type(e).__name__}: {e}", "err")
        sys.exit(1)

    if not urls:
        log("no URLs matched the filters", "err")
        sys.exit(1)

    log(f"read {stats_load['read']} lines from {urls_file.name}", "info")
    for k, label in [("invalid", "invalid"), ("filtered_url", "filtered by URL regex"),
                     ("filtered_host", "filtered by host"), ("filtered_path", "filtered by path"),
                     ("dupes", "duplicates removed")]:
        if stats_load[k]:
            log(f"  {stats_load[k]} {label}", "info")
    log(f"kept {stats_load['kept']} unique URLs", "ok")

    print_host_stats(urls)
    if args.stats_only:
        print_path_stats(urls)
        return

    if args.dry_run:
        section("DRY RUN — no fetch, no write")
        log(f"would fetch {len(urls)} URLs into {workspace}", "info")
        if args.ai:
            log("would run AI recon (provider auto-picked from .env)", "info")
        print_path_stats(urls)
        return

    # ---- Workspace dirs -------------------------------------------------
    try:
        (workspace / "sites").mkdir(parents=True, exist_ok=True)
        (workspace / "findings").mkdir(parents=True, exist_ok=True)
        (workspace / "recon").mkdir(parents=True, exist_ok=True)
        (workspace / "headers").mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log(f"cannot create workspace: {type(e).__name__}: {e}", "err")
        sys.exit(1)

    # ---- Header profiles ------------------------------------------------
    section("AUTHENTICATION")
    cli_headers = parse_extra_headers(args.cookie, args.header)

    if args.no_auth:
        log("--no-auth set: skipping header profiles", "warn")
        header_jar = None
        fallback_headers = cli_headers
    else:
        headers_dir = Path(args.headers_dir) if args.headers_dir else (workspace / "headers")
        try:
            header_jar = HeaderJar(headers_dir, cli_headers=cli_headers)
            header_jar.load()
        except Exception as e:
            log(f"failed to load header profiles: {type(e).__name__}: {e}", "warn")
            header_jar = None
            fallback_headers = cli_headers
        else:
            profiles = header_jar.profiles_loaded()
            if profiles:
                log(f"header profiles loaded from {headers_dir}", "ok")
                for name, count in profiles:
                    log(f"  {name:<28} {count} headers", "info")
            else:
                log(f"no header profiles in {headers_dir}", "info")
                if cli_headers:
                    log(f"using {len(cli_headers)} CLI header(s)", "info")
                else:
                    log("unauthenticated fetch — scanners may miss auth bugs", "warn")
            fallback_headers = cli_headers

    # ---- AI availability -----------------------------------------------
    section("AI AVAILABILITY")
    ai_client = None
    ai_semaphore = None

    env_path = find_env_file()
    if env_path:
        log(f".env         : {env_path}", "info", "AI")
    else:
        log(".env         : not found (checking os.environ only)", "info", "AI")

    env = load_env()
    rows = provider_summary(env)
    usable_names = [r["provider"] for r in rows if r["usable"]]
    for r in rows:
        icon = "ready" if r["usable"] else "--"
        log(f"  {r['label']:<14} {icon:<6} {r['env_var'] or '(not set)'}", "info", "AI")

    if not args.ai:
        log("--ai not passed → fetch-only mode", "info", "AI")
    elif not usable_names:
        log("--ai passed but NO provider key resolved", "warn", "AI")
        log("  → add keys to .env (see env_example)", "info", "AI")
        log("  → URLs will still be fetched and saved", "info", "AI")
    else:
        prefer = None
        if args.ai_provider:
            if args.ai_provider not in AI_PROVIDERS:
                log(f"unknown provider: {args.ai_provider}", "err", "AI")
                sys.exit(1)
            if args.ai_provider not in usable_names:
                log(f"--ai-provider {args.ai_provider} has no key — auto-picking",
                    "warn", "AI")
            else:
                prefer = args.ai_provider

        try:
            ai_client = AIClient(prefer=prefer, timeout=args.ai_timeout)
        except Exception as e:
            log(f"AI client init failed: {type(e).__name__}: {e}", "warn", "AI")
            ai_client = None

        if ai_client and ai_client.available():
            log("AI recon    : ON", "ok", "AI")
            log(f"  provider  : {ai_client.label} ({ai_client.provider})", "info", "AI")
            log(f"  model     : {ai_client.model}", "info", "AI")
            log(f"  workers   : {args.ai_workers}", "info", "AI")
            log(f"  timeout   : {args.ai_timeout}s per call", "info", "AI")
            if args.ai_skip_static:
                log("  skip-static: ON", "info", "AI")
            if args.ai_force:
                log("  force     : ON (ignore cache)", "info", "AI")
            ai_semaphore = threading.Semaphore(max(1, args.ai_workers))
        else:
            log("AI client could not initialise — proceeding without AI", "warn", "AI")

    # ---- Write import metadata -----------------------------------------
    try:
        save_json(workspace / "_burp_import.json", {
            "trident_version": TRIDENT_VERSION,
            "source_file": str(urls_file),
            "preset": args.preset,
            "filters_applied": {k: v for k, v in filters.items() if v},
            "load_stats": stats_load,
            "total_urls": len(urls),
            "auth": {
                "enabled": header_jar is not None,
                "headers_dir": str(Path(args.headers_dir) if args.headers_dir
                                    else (workspace / "headers")),
                "profiles": header_jar.profiles_loaded() if header_jar else [],
                "cli_header_names": sorted(cli_headers.keys()),
                "no_auth_flag": args.no_auth,
            },
            "ai": {
                "requested": args.ai,
                "usable_providers": usable_names,
                "provider_used": (ai_client.provider
                                    if (ai_client and ai_client.available()) else None),
                "model_used": (ai_client.model
                                if (ai_client and ai_client.available()) else None),
                "workers": args.ai_workers,
                "timeout": args.ai_timeout,
                "skip_static": args.ai_skip_static,
                "force": args.ai_force,
            },
            "refresh": args.refresh,
            "no_fetch": args.no_fetch,
            "timestamp": now_iso(),
        })
    except Exception as e:
        log(f"failed to write import metadata: {type(e).__name__}: {e}", "warn")

    # ---- Fetch ---------------------------------------------------------
    section("FETCHING" if not args.no_fetch else "REGISTERING (no fetch)")
    if args.no_fetch:
        log(f"registering {len(urls)} URLs without fetching", "info")
    else:
        log(f"fetching {len(urls)} URLs "
            f"(workers={args.workers}, delay={args.delay}s/host, "
            f"timeout={CONNECT_TIMEOUT}s connect / {args.timeout}s read, "
            f"dead-after={args.dead_after})", "info")

    used_slugs = {}
    used_slugs_lock = threading.Lock()
    throttle = HostThrottle(args.delay)
    circuit = HostCircuitBreaker(limit=args.dead_after)
    stats = FetchStats(total=len(urls))
    out_lock = threading.Lock()

    t0 = time.time()
    last_progress = [0]

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {pool.submit(
                fetch_worker, u, workspace, used_slugs, used_slugs_lock,
                throttle, header_jar, fallback_headers,
                args.no_fetch, args.refresh,
                ai_client, ai_semaphore, args.ai_force, args.ai_skip_static,
                stats, out_lock, args.quiet, circuit,
            ): u for u in urls}

            done = 0
            for fut in as_completed(futures):
                url = futures[fut]
                done += 1
                try:
                    _, status, outcome = fut.result()
                except Exception as e:
                    stats.bump("failed")
                    stats.record_error(f"worker:{type(e).__name__}")
                    if not args.quiet:
                        log(f"  ✗ worker crash for {url[:80]}: "
                            f"{type(e).__name__}: {e}", "warn")
                    continue

                if outcome == "skipped_dead":
                    pass
                elif outcome == "skipped":
                    if not args.quiet:
                        log(f"  · [cached] {url[:110]}", "info")
                elif outcome.startswith("error:"):
                    stats.bump("failed")
                    if not args.quiet:
                        log(f"  ✗ [{outcome.split(':', 1)[1]}] {url[:110]}", "warn")
                else:
                    if not args.quiet:
                        log(f"  ✓ [{status}] {url[:110]}", "ok",
                            urlparse(url).netloc)

                # Progress
                if done - last_progress[0] >= PROGRESS_EVERY or done == len(urls):
                    last_progress[0] = done
                    snap = stats.snapshot()
                    el = time.time() - t0
                    rate = done / el if el > 0 else 0
                    eta = (len(urls) - done) / rate if rate > 0 else 0
                    log(f"progress {done}/{len(urls)}  "
                        f"ok={snap['written']} fail={snap['failed']} "
                        f"skip={snap['skipped']} dead-skip={snap['dead_skipped']}  "
                        f"~{rate:.1f}/s  ETA {format_duration(eta)}",
                        "info", "PROG")

    except KeyboardInterrupt:
        print()
        log("interrupted — partial workspace preserved", "warn")

    elapsed = time.time() - t0

    # ---- Collect AI index from disk -----------------------------------
    ai_results = []
    if ai_client is not None and ai_client.available():
        try:
            for jf in (workspace / "sites").rglob("*.json"):
                if jf.name.startswith("_"):
                    continue
                try:
                    rec = load_json(jf)
                except Exception:
                    continue
                ar = rec.get("ai_recon")
                if ar:
                    ar2 = dict(ar)
                    ar2["url"] = rec.get("url", "")
                    ai_results.append(ar2)
        except Exception as e:
            log(f"failed to collect AI index: {type(e).__name__}: {e}", "warn")

    # ---- Summary --------------------------------------------------------
    snap = stats.snapshot()
    dead = circuit.dead_hosts()

    section("SUMMARY")
    log(f"workspace     : {workspace}", "ok")
    log(f"unique hosts  : {len(set(urlparse(u).netloc for u in urls))}", "info")
    log(f"pages written : {snap['written']}", "ok")
    if snap["skipped"]:
        log(f"pages skipped : {snap['skipped']} (already existed)", "info")
    if snap["refreshed"]:
        log(f"pages refreshed: {snap['refreshed']}", "info")
    if snap["failed"]:
        log(f"pages failed  : {snap['failed']} (saved with _error)", "warn")
    if snap["dead_skipped"]:
        log(f"dead-host skip: {snap['dead_skipped']} URLs skipped", "warn")
    if snap["authenticated"] or snap["unauthenticated"]:
        log(f"authenticated : {snap['authenticated']}  |  "
            f"unauthenticated : {snap['unauthenticated']}", "info")
    if snap["error_reasons"]:
        reasons = sorted(snap["error_reasons"].items(), key=lambda x: -x[1])
        log("error breakdown: " + "  ".join(f"{r}={n}" for r, n in reasons[:6]), "info")
    if dead:
        log(f"dead hosts    : {len(dead)} (≥{args.dead_after} consecutive failures)", "warn")
        for h, n in sorted(dead.items(), key=lambda x: -x[1])[:10]:
            log(f"  {h:<42} {n} failures", "info")
    log(f"elapsed       : {format_duration(elapsed)}", "info")

    if ai_client is not None and ai_client.available():
        print_ai_summary(stats, ai_client)

    if ai_results:
        try:
            n = write_ai_index(workspace, ai_results)
            log(f"priority index: {n} pages  ({workspace / '_ai_recon_index.json'})",
                "ok", "AI")
        except Exception as e:
            log(f"failed to write priority index: {type(e).__name__}: {e}", "warn")

    # Final metadata merge
    try:
        final = load_json(workspace / "_burp_import.json")
    except Exception:
        final = {}
    final["final_stats"] = snap
    final["dead_hosts"] = dead
    final["completed_at"] = now_iso()
    if ai_client is not None:
        final["ai"]["usage"] = dict(ai_client.stats)
    try:
        save_json(workspace / "_burp_import.json", final)
    except Exception:
        pass

    print()
    print(f"{C.D}Next steps:{C.R}")
    print()
    if ai_results:
        print(f"  {C.CY}AI priority index:{C.R} {workspace / '_ai_recon_index.json'}")
        high = [x for x in ai_results if x.get("priority") == "high"][:5]
        if high:
            print(f"  {C.D}High-priority pages (scan these first):{C.R}")
            for r in high:
                print(f"    · {r.get('url', '')[:80]} "
                      f"[{','.join(r.get('suggested_scanners', []))}]")
        print()

    print(f"  python3 sqli.py           {workspace}")
    print(f"  python3 xss.py            {workspace} --browser")
    print(f"  python3 ssrf.py           {workspace}")
    print(f"  python3 open_redirect.py  {workspace}")
    print(f"  python3 path_traversal.py {workspace}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
        sys.exit(130)
