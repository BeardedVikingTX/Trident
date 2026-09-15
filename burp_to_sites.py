#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TRIDENT :: burp_to_sites.py — v1.0.0
#  Convert Burp Suite URL exports into the workspace/<host>/<slug>.json
#  format that the TRIDENT scanners consume.
# -----------------------------------------------------------------------------
#  What's here:
#    · Preset filters (bugbounty / strict / api-only / none)
#    · Host + path include/exclude regexes
#    · Tracking-parameter stripping + static-asset skipping
#    · Per-URL fetch with auth header profiles (workspace/headers/*.txt)
#    · AI page reconnaissance — AUTO-DETECTS which provider is usable
#    · Resume mode, --refresh, --dry-run, --stats-only
#    · Priority index (_ai_recon_index.json) for scan ordering
#    · Multi-provider AI: Groq, DeepSeek, OpenAI, Gemini, Anthropic
#    · Workspace metadata (_burp_import.json) with full audit trail
# -----------------------------------------------------------------------------
#  AI behavior (the important part):
#
#    If --ai is passed AND at least one provider key resolves:
#        → AI recon runs on every non-static, non-cached page
#        → the winner provider is logged up-front
#        → pages that fail AI are still written (with _ai.ok=false)
#
#    If --ai is passed but NO provider key resolves:
#        → warn once, continue fetching, skip AI entirely
#        → _ai block records enabled=true, ok=false, reason="no_provider"
#
#    If --ai is NOT passed:
#        → _ai block records enabled=false
#        → fetch-only mode
# =============================================================================

import argparse
import hashlib
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

# -----------------------------------------------------------------------------
#  TRIDENT utilities (the new single source of truth)
# -----------------------------------------------------------------------------
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
        "description": "Balanced — skips CDNs, static assets, third-party hosts (DEFAULT)",
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
        "description": "Paranoid — only API-like endpoints, no static content",
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
    "none": {"description": "No automatic filtering — raw import"},
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

MAX_BODY_BYTES     = 500_000
FETCH_TIMEOUT      = 20
DEFAULT_DELAY      = 0.25
DEFAULT_WORKERS    = 8
DEFAULT_AI_WORKERS = 2
PROGRESS_EVERY     = 25

AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token",
    "proxy-authorization", "x-amz-security-token", "x-goog-api-key",
}


# =============================================================================
#  AI CLIENT  (self-contained — no brain.py needed)
# =============================================================================
class AIClient:
    """
    Thin multi-provider chat client. Uses the provider picked by
    trident_utils.pick_provider() and speaks the right dialect for
    each backend.
    """

    def __init__(self, prefer=None, timeout=45, max_tokens=1400):
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
            self.model = None
            self.label = None
            self.key = None

        # usage tracking
        self._usage_lock = threading.Lock()
        self.stats = {
            "calls": 0, "ok": 0, "failed": 0,
            "tokens_in": 0, "tokens_out": 0,
        }

    # ------------------------------------------------------------------ #
    def available(self):
        return bool(self.provider and self.key)

    # ------------------------------------------------------------------ #
    def _bump(self, ok, tokens_in=0, tokens_out=0):
        with self._usage_lock:
            self.stats["calls"] += 1
            if ok:
                self.stats["ok"] += 1
            else:
                self.stats["failed"] += 1
            self.stats["tokens_in"] += tokens_in
            self.stats["tokens_out"] += tokens_out

    # ------------------------------------------------------------------ #
    def chat(self, system_prompt, user_prompt, json_mode=True):
        """
        Send a chat completion. Returns (text_or_None, usage_dict).
        """
        if not self.available():
            return None, {}

        p = self.provider
        try:
            if p in ("groq", "deepseek", "openai"):
                return self._openai_compat(system_prompt, user_prompt, json_mode)
            if p == "gemini":
                return self._gemini(system_prompt, user_prompt, json_mode)
            if p == "anthropic":
                return self._anthropic(system_prompt, user_prompt)
            if p == "huggingface":
                return self._huggingface(system_prompt, user_prompt)
            if p == "ollama":
                return self._ollama(system_prompt, user_prompt, json_mode)
        except Exception as e:
            log("AI call failed ({}): {}: {}".format(p, type(e).__name__, e),
                "warn", "AI")
            self._bump(ok=False)
            return None, {}

        log("AI provider {} not supported for calls yet".format(p),
            "warn", "AI")
        return None, {}

    # ------------------------------------------------------------------ #
    def _openai_compat(self, sys_p, user_p, json_mode):
        cfg = AI_PROVIDERS[self.provider]
        url = cfg["base_url"].rstrip("/") + "/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user",   "content": user_p},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": "Bearer {}".format(self.key),
            "Content-Type": "application/json",
        }
        r = send_request(url, method="POST", headers=headers,
                         json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            status = r.status_code if r else "no_response"
            log("{} HTTP {}".format(self.provider, status),
                "warn", "AI")
            self._bump(ok=False)
            return None, {}
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {}) or {}
        self._bump(ok=True,
                   tokens_in=usage.get("prompt_tokens", 0),
                   tokens_out=usage.get("completion_tokens", 0))
        return text, usage

    # ------------------------------------------------------------------ #
    def _gemini(self, sys_p, user_p, json_mode):
        url = "{}/models/{}:generateContent?key={}".format(
            AI_PROVIDERS["gemini"]["base_url"], self.model, self.key)
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": sys_p + "\n\n" + user_p}]}
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": self.max_tokens,
            },
        }
        if json_mode:
            body["generationConfig"]["responseMimeType"] = "application/json"

        r = send_request(url, method="POST", json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            status = r.status_code if r else "no_response"
            log("gemini HTTP {}".format(status), "warn", "AI")
            self._bump(ok=False)
            return None, {}
        data = r.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            text = ""
        usage = data.get("usageMetadata", {}) or {}
        self._bump(ok=True,
                   tokens_in=usage.get("promptTokenCount", 0),
                   tokens_out=usage.get("candidatesTokenCount", 0))
        return text, usage

    # ------------------------------------------------------------------ #
    def _anthropic(self, sys_p, user_p):
        url = AI_PROVIDERS["anthropic"]["base_url"].rstrip("/") + "/messages"
        headers = {
            "x-api-key": self.key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": sys_p,
            "messages": [{"role": "user", "content": user_p}],
        }
        r = send_request(url, method="POST", headers=headers,
                         json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            status = r.status_code if r else "no_response"
            log("anthropic HTTP {}".format(status), "warn", "AI")
            self._bump(ok=False)
            return None, {}
        data = r.json()
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        usage = data.get("usage", {}) or {}
        self._bump(ok=True,
                   tokens_in=usage.get("input_tokens", 0),
                   tokens_out=usage.get("output_tokens", 0))
        return text, usage

    # ------------------------------------------------------------------ #
    def _huggingface(self, sys_p, user_p):
        url = "{}/models/{}".format(
            AI_PROVIDERS["huggingface"]["base_url"].rstrip("/"), self.model)
        headers = {"Authorization": "Bearer {}".format(self.key)}
        body = {
            "inputs": sys_p + "\n\n" + user_p,
            "parameters": {"max_new_tokens": self.max_tokens,
                           "temperature": 0.2,
                           "return_full_text": False},
        }
        r = send_request(url, method="POST", headers=headers,
                         json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            status = r.status_code if r else "no_response"
            log("huggingface HTTP {}".format(status), "warn", "AI")
            self._bump(ok=False)
            return None, {}
        try:
            data = r.json()
            if isinstance(data, list) and data:
                text = data[0].get("generated_text", "")
            else:
                text = str(data)
        except Exception:
            text = ""
        self._bump(ok=True)
        return text, {}

    # ------------------------------------------------------------------ #
    def _ollama(self, sys_p, user_p, json_mode):
        url = AI_PROVIDERS["ollama"]["base_url"].rstrip("/") + "/api/chat"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user",   "content": user_p},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }
        if json_mode:
            body["format"] = "json"
        r = send_request(url, method="POST", json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            self._bump(ok=False)
            return None, {}
        data = r.json()
        text = (data.get("message") or {}).get("content", "")
        self._bump(ok=True,
                   tokens_in=data.get("prompt_eval_count", 0),
                   tokens_out=data.get("eval_count", 0))
        return text, {}

    # ------------------------------------------------------------------ #
    def recon_page(self, page):
        """
        Run AI reconnaissance on a fetched page.
        Returns dict (recon) or None on failure.
        """
        if not self.available():
            return None

        # Strip body to keep tokens sane — 6 KB of HTML is plenty
        body = (page.get("content") or "")[:6000]
        url = page.get("url", "")
        status = page.get("status", 0)
        ctype = page.get("content_type", "")
        params = page.get("params", [])
        title = page.get("title", "")
        headers_safe = {
            k: mask_header_value(k, v)
            for k, v in (page.get("headers") or {}).items()
            if k.lower() in ("server", "x-powered-by", "content-type",
                             "x-frame-options", "strict-transport-security",
                             "content-security-policy", "x-csrf-token")
        }

        system = (
            "You are a bug bounty reconnaissance analyst. You receive an "
            "HTTP page snapshot and output STRICT JSON describing its attack "
            "surface. No prose. No markdown. JSON only."
        )

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

Return ONLY this JSON schema — no surrounding text:
{{
  "kind": "api|form|auth|admin|static|error|landing|other",
  "priority": "high|medium|low",
  "interesting": true or false,
  "confidence": 0.0 to 1.0,
  "attack_surface": ["url_params", "forms", "json_body", "cookies", "headers", "graphql", "file_upload"],
  "suggested_scanners": ["sqli", "xss", "ssrf", "open_redirect", "path_traversal"],
  "notes": "one short sentence"
}}

Rules:
- "high" priority = auth flows, admin panels, APIs taking user input, file ops
- "medium" = forms, search, params that look processed
- "low" = static pages, marketing, legal, error pages
- interesting = true only if there is plausible injection or auth surface
- Confidence reflects how sure you are given only this snapshot
"""

        text, usage = self.chat(system, user, json_mode=True)
        if not text:
            return None

        # Parse JSON — tolerate code fences
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

        # Normalize
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
        cleaned = {k: v for k, v in qs.items()
                   if k.lower() not in TRACKING_PARAMS}
        new_query = urlencode(cleaned, doseq=True) if cleaned else ""
        p = p._replace(query=new_query)
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

    rx_filter    = re.compile(filter_pattern) if filter_pattern else None
    rx_inc_host  = re.compile(include_host)   if include_host else None
    rx_exc_host  = re.compile(exclude_host)   if exclude_host else None
    rx_inc_path  = re.compile(include_path)   if include_path else None
    rx_exc_path  = re.compile(exclude_path)   if exclude_path else None

    stats = {
        "read": 0, "invalid": 0, "filtered_url": 0,
        "filtered_host": 0, "filtered_path": 0,
        "dupes": 0, "kept": 0,
    }

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            stats["read"] += 1
            line = parse_url_line(raw)
            if not line:
                stats["invalid"] += 1
                continue
            line = normalize_url(line)
            if not line:
                stats["invalid"] += 1
                continue
            if rx_filter and not rx_filter.search(line):
                stats["filtered_url"] += 1
                continue
            try:
                parsed = urlparse(line)
            except Exception:
                stats["invalid"] += 1
                continue
            host = parsed.netloc.lower()
            path_l = parsed.path.lower()

            if rx_inc_host and not rx_inc_host.search(host):
                stats["filtered_host"] += 1; continue
            if rx_exc_host and rx_exc_host.search(host):
                stats["filtered_host"] += 1; continue
            if rx_inc_path and not rx_inc_path.search(path_l):
                stats["filtered_path"] += 1; continue
            if rx_exc_path and rx_exc_path.search(path_l):
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
        qs_slug = "_".join(
            "{}={}".format(k, v[0]) for k, v in sorted(parse_qs(parsed.query).items())
        )
        path_part = "{}__{}".format(path_part, qs_slug)
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
    for marker in ("cdn.", ".cdn.", "static.", "assets.",
                   "img.", "images.", "fonts.", "jsdelivr",
                   "gstatic", "googleapis"):
        if marker in host:
            return True
    return False


# =============================================================================
#  HTTP FETCH
# =============================================================================
def _categorize_error(exc_type_name, msg):
    m = (msg or "").lower()
    if "timeout" in m or "timed out" in m:                      return "timeout"
    if "name or service not known" in m or "getaddrinfo" in m:  return "dns"
    if "ssl" in m or "certificate" in m:                        return "tls"
    if "connection refused" in m:                               return "refused"
    if "connection reset" in m:                                 return "reset"
    return "exception:{}".format(exc_type_name)


def describe_fetch_headers(merged_headers):
    if not merged_headers:
        return False, []
    names = sorted(merged_headers.keys())
    authed = any(n.lower() in AUTH_HEADER_NAMES for n in names)
    return authed, names


def fetch_page(url, timeout=FETCH_TIMEOUT, extra_headers=None):
    try:
        r = send_request(url, timeout=timeout, allow_redirects=True,
                         headers=extra_headers)
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


def placeholder_page(url):
    parsed = urlparse(url)
    return {
        "url": url, "status": 200, "method": "GET",
        "content_type": "text/html", "content_length": 0, "title": "",
        "params": list(parse_qs(parsed.query).keys()),
        "headers": {}, "cookies": {}, "content": "",
        "_source": "burp_placeholder",
        "_note": "no content captured — scanners will test URL params only",
        "_fetched_at": now_iso(),
    }


# =============================================================================
#  STATS
# =============================================================================
class FetchStats:
    def __init__(self, total):
        self.total = total
        self.written = self.failed = self.skipped = self.refreshed = 0
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
            else:      self.unauthenticated += 1

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
                "authenticated": self.authenticated,
                "unauthenticated": self.unauthenticated,
                "ai_done": self.ai_done, "ai_failed": self.ai_failed,
                "ai_skipped": self.ai_skipped, "ai_interesting": self.ai_interesting,
                "ai_by_kind": dict(self.ai_by_kind),
                "ai_by_priority": dict(self.ai_by_priority),
                "ai_scanner_hits": dict(self.ai_scanner_hits),
                "error_reasons": dict(self.error_reasons),
                "elapsed_s": round(time.time() - self.started_at, 1),
            }


# =============================================================================
#  THROTTLE
# =============================================================================
class HostThrottle:
    def __init__(self, delay):
        self.delay = delay
        self._last, self._lock = {}, threading.Lock()

    def wait(self, host):
        if self.delay <= 0 or not host:
            return
        with self._lock:
            now = time.time()
            last = self._last.get(host, 0.0)
            w = self.delay - (now - last)
            if w > 0:
                time.sleep(w)
                now = time.time()
            self._last[host] = now


# =============================================================================
#  WORKER
# =============================================================================
def fetch_worker(url, workspace, used_slugs, used_slugs_lock, throttle,
                 header_jar, fallback_headers, no_fetch, refresh,
                 ai_client, ai_semaphore, ai_force, ai_skip_static,
                 stats, out_lock, quiet):

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    host_dir = workspace / "sites" / safe_filename(host)
    try:
        host_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        stats.record_error("mkdir:OSError")
        return url, 0, "error:mkdir"

    slug = slug_for_url(url)
    with used_slugs_lock:
        host_slugs = used_slugs.setdefault(host, {})
        if slug in host_slugs:
            h = hashlib.md5(url.encode()).hexdigest()[:6]
            slug = "{}_{}".format(slug, h)
        host_slugs[slug] = url

    out_path = host_dir / "{}.json".format(slug)

    # Resume
    record = None
    needs_save = False
    if out_path.exists() and not refresh:
        try:
            record = load_json(out_path)
            needs_ai = (ai_client is not None and ai_client.available()
                        and "ai_recon" not in record)
            if not needs_ai:
                stats.bump("skipped")
                return url, record.get("status", 0), "skipped"
        except Exception:
            record = None

    # Fetch
    if record is None:
        if header_jar is not None:
            merged_headers = header_jar.headers_for(url)
        else:
            merged_headers = dict(fallback_headers or {})
        authed, header_names = describe_fetch_headers(merged_headers)

        if no_fetch:
            record = placeholder_page(url)
            outcome = "placeholder"
        else:
            throttle.wait(host)
            record, err = fetch_page(url, extra_headers=merged_headers)
            if record is None:
                stats.record_error(err or "unknown")
                return url, 0, "error:{}".format(err or "unknown")
            outcome = "ok"

        record["_fetch"] = {
            "authenticated": authed,
            "header_names":  header_names,
            "timestamp":     now_iso(),
        }
        stats.record_auth(authed)
        if refresh and out_path.exists():
            stats.bump("refreshed")
        needs_save = True

    # AI recon
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
            try:
                with ai_semaphore:
                    recon = ai_client.recon_page(record)
                ai_ok = recon is not None
            except Exception as e:
                ai_ok = False
                if not quiet:
                    log("AI recon error for {}: {}: {}".format(
                        url[:80], type(e).__name__, e), "warn")
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
            needs_save = True
        else:
            if "_ai" not in record:
                record["_ai"] = {
                    "enabled":   True,
                    "ok":        "ai_recon" in record,
                    "provider":  ai_client.provider,
                    "model":     ai_client.model,
                    "model_label": ai_client.label,
                    "skipped":   True,
                    "timestamp": now_iso(),
                }
                needs_save = True
    else:
        # No AI at all — stamp the record so scanners know
        if "_ai" not in record:
            record["_ai"] = {
                "enabled":   False,
                "reason":    "no_provider" if ai_client is None else "disabled",
                "timestamp": now_iso(),
            }
            needs_save = True

    if needs_save:
        try:
            with out_lock:
                save_json(out_path, record)
            stats.bump("written")
        except Exception as e:
            stats.record_error("save:{}".format(type(e).__name__))
            return url, record.get("status", 0), "error:save"

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
    print("{}  {:<52} {:>6}{}".format(C.B + C.WH, "HOST", "URLS", C.R))
    print("{}  {}{}".format(C.D, "─" * 60, C.R))
    for host, count in sh[:top]:
        h = host[:50] + ".." if len(host) > 52 else host
        print("  {:<52} {:>6}".format(h, count))
    if len(sh) > top:
        remaining = sum(c for _, c in sh[top:])
        print("  {}... and {} more hosts ({} URLs){}".format(
            C.D, len(sh) - top, remaining, C.R))
    print("{}  {}{}".format(C.D, "─" * 60, C.R))
    print("  {:<52} {:>6}".format("TOTAL", len(urls)))
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
    print("{}  {:<52} {:>6}{}".format(C.B + C.WH, "PATH PREFIX", "URLS", C.R))
    print("{}  {}{}".format(C.D, "─" * 60, C.R))
    for prefix, count in sp[:top]:
        p = prefix[:50] + ".." if len(prefix) > 52 else prefix
        print("  {:<52} {:>6}".format(p, count))
    print()


def print_ai_summary(stats, ai_client):
    snap = stats.snapshot()
    if not (snap["ai_done"] or snap["ai_failed"] or snap["ai_skipped"]):
        return
    section("AI RECON SUMMARY")
    log("provider      : {} / {}".format(ai_client.label, ai_client.model), "info")
    log("analyzed      : {} pages".format(snap["ai_done"]), "ok")
    if snap["ai_interesting"]:
        pct = 100.0 * snap["ai_interesting"] / max(1, snap["ai_done"])
        log("interesting   : {} ({:.0f}%)".format(snap["ai_interesting"], pct), "info")
    if snap["ai_skipped"]:
        log("skipped       : {} (static or cached)".format(snap["ai_skipped"]), "info")
    if snap["ai_failed"]:
        log("failed        : {}".format(snap["ai_failed"]), "warn")
    if snap["ai_by_priority"]:
        p = snap["ai_by_priority"]
        log("by priority   : high={} medium={} low={}".format(
            p.get("high", 0), p.get("medium", 0), p.get("low", 0)), "info")
    if snap["ai_scanner_hits"]:
        s = sorted(snap["ai_scanner_hits"].items(), key=lambda x: -x[1])
        log("scanner hints : " + "  ".join(
            "{}={}".format(n, c) for n, c in s[:8]), "info")
    st = ai_client.stats
    log("usage         : {} calls ({} ok / {} fail)  tokens {}/{}".format(
        st["calls"], st["ok"], st["failed"],
        st["tokens_in"], st["tokens_out"]), "info")


def write_ai_index(workspace, results):
    index = {
        "generated_at": now_iso(),
        "total": len(results),
        "pages": [],
    }
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
        description="Burp URLs → TRIDENT workspace (auth-aware, AI-optional)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
AI provider auto-selection:
  Checks .env / os.environ for keys in this order:
    groq → gemini → deepseek → openai → anthropic → huggingface → ollama
  The first usable provider wins. Override with --ai-provider <name>.

Header profiles:
  workspace/headers/default.txt           applies to every host
  workspace/headers/<host>.txt            applies to that host only
  Supports raw header lines OR full Burp request blocks (HTTP/1-2).

Examples:
  python3 burp_to_sites.py urls.txt workspace/
  python3 burp_to_sites.py urls.txt workspace/ --ai
  python3 burp_to_sites.py urls.txt workspace/ --ai --ai-provider groq
  python3 burp_to_sites.py urls.txt workspace/ --no-auth
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
    ap.add_argument("--no-fetch", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--stats-only", action="store_true")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--timeout", type=int, default=FETCH_TIMEOUT)
    ap.add_argument("-q", "--quiet", action="store_true")

    # Auth
    ap.add_argument("--headers-dir", default=None)
    ap.add_argument("--no-auth", action="store_true")
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--header", action="append", default=[])

    # AI
    ap.add_argument("--ai", action="store_true",
                    help="enable AI page reconnaissance")
    ap.add_argument("--ai-provider", default=None,
                    help="force a specific provider (default: auto-pick)")
    ap.add_argument("--ai-workers", type=int, default=DEFAULT_AI_WORKERS)
    ap.add_argument("--ai-force", action="store_true")
    ap.add_argument("--ai-skip-static", action="store_true")

    return ap


def merge_preset_filters(args):
    preset = PRESETS.get(args.preset, {})
    result = {
        "filter":       args.filter,
        "include_host": args.include_host,
        "exclude_host": args.exclude_host,
        "include_path": args.include_path,
        "exclude_path": args.exclude_path,
    }
    for key in ("include_host", "exclude_host", "include_path", "exclude_path"):
        if result[key] is None and key in preset:
            result[key] = preset[key]
    if args.no_cdn:
        cdn_rx = (r"(cdn\.|\.cdn\.|akamai|cloudfront|cloudflare|fastly|"
                  r"\.googleapis\.com|\.gstatic\.com|\.jsdelivr\.net)")
        if result["exclude_host"]:
            result["exclude_host"] = "({})|({})".format(
                result["exclude_host"], cdn_rx)
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

    urls_file = Path(args.urls_file)
    if not urls_file.exists():
        log("URLs file not found: {}".format(urls_file), "err")
        sys.exit(1)

    workspace = Path(args.workspace)
    preset_info = PRESETS.get(args.preset, {})
    if preset_info.get("description"):
        log("preset : {} — {}".format(args.preset, preset_info["description"]),
            "info")

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
        log("failed to load URLs: {}: {}".format(type(e).__name__, e), "err")
        sys.exit(1)

    if not urls:
        log("no URLs matched the filters", "err")
        sys.exit(1)

    log("read {} lines from {}".format(stats_load["read"], urls_file.name), "info")
    for k, label in [
        ("invalid",       "invalid"),
        ("filtered_url",  "filtered by URL regex"),
        ("filtered_host", "filtered by host"),
        ("filtered_path", "filtered by path"),
        ("dupes",         "duplicates removed"),
    ]:
        if stats_load[k]:
            log("  {} {}".format(stats_load[k], label), "info")
    log("kept {} unique URLs".format(stats_load["kept"]), "ok")

    print_host_stats(urls)
    if args.stats_only:
        print_path_stats(urls)
        return

    if args.dry_run:
        section("DRY RUN — no fetch, no write")
        log("would fetch {} URLs into {}".format(len(urls), workspace), "info")
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
        log("cannot create workspace: {}: {}".format(type(e).__name__, e), "err")
        sys.exit(1)

    # ---- Header profiles ------------------------------------------------
    section("AUTHENTICATION")
    cli_headers = parse_extra_headers(args.cookie, args.header)

    if args.no_auth:
        log("--no-auth set: skipping header profiles", "warn")
        header_jar = None
        fallback_headers = cli_headers
    else:
        headers_dir = (Path(args.headers_dir) if args.headers_dir
                       else (workspace / "headers"))
        try:
            header_jar = HeaderJar(headers_dir, cli_headers=cli_headers)
            header_jar.load()
        except Exception as e:
            log("failed to load header profiles: {}: {}".format(
                type(e).__name__, e), "warn")
            header_jar = None
            fallback_headers = cli_headers
        else:
            profiles = header_jar.profiles_loaded()
            if profiles:
                log("header profiles loaded from {}".format(headers_dir), "ok")
                for name, count in profiles:
                    log("  {:<28} {} headers".format(name, count), "info")
            else:
                log("no header profiles in {}".format(headers_dir), "info")
                if cli_headers:
                    log("using {} CLI header(s)".format(len(cli_headers)), "info")
                else:
                    log("unauthenticated fetch — scanners may miss auth bugs",
                        "warn")
            fallback_headers = cli_headers

    # ---- AI availability -----------------------------------------------
    section("AI AVAILABILITY")
    ai_client = None
    ai_semaphore = None

    # Always show the .env state
    env_path = find_env_file()
    if env_path:
        log(".env         : {}".format(env_path), "info")
    else:
        log(".env         : not found (checking os.environ only)", "info")

    env = load_env()
    rows = provider_summary(env)
    usable_names = [r["provider"] for r in rows if r["usable"]]
    for r in rows:
        icon = "ready" if r["usable"] else "--"
        log("  {:<14} {:<6} {}".format(r["label"], icon,
                                        r["env_var"] or "(not set)"), "info")

    if not args.ai:
        log("--ai not passed → fetch-only mode (no AI recon)", "info")
    elif not usable_names:
        log("--ai passed but NO provider key resolved", "warn")
        log("  → add keys to .env (see env_example)", "info")
        log("  → continuing without AI", "info")
    else:
        if args.ai_provider:
            if args.ai_provider not in AI_PROVIDERS:
                log("unknown provider: {}".format(args.ai_provider), "err")
                sys.exit(1)
            if args.ai_provider not in usable_names:
                log("--ai-provider {} has no key — auto-picking".format(
                    args.ai_provider), "warn")
                prefer = None
            else:
                prefer = args.ai_provider
        else:
            prefer = None

        try:
            ai_client = AIClient(prefer=prefer, timeout=args.timeout * 3)
        except Exception as e:
            log("AI client init failed: {}: {}".format(type(e).__name__, e),
                "warn")
            ai_client = None

        if ai_client and ai_client.available():
            log("AI recon    : ON", "ok")
            log("  provider  : {} ({})".format(ai_client.label,
                                                ai_client.provider), "info")
            log("  model     : {}".format(ai_client.model), "info")
            log("  workers   : {}".format(args.ai_workers), "info")
            if args.ai_skip_static:
                log("  skip-static: ON", "info")
            if args.ai_force:
                log("  force     : ON (ignore cache)", "info")
            ai_semaphore = threading.Semaphore(max(1, args.ai_workers))
        else:
            log("AI client could not initialise — proceeding without AI", "warn")

    # ---- Write import metadata -----------------------------------------
    try:
        save_json(workspace / "_burp_import.json", {
            "trident_version":  TRIDENT_VERSION,
            "source_file":      str(urls_file),
            "preset":           args.preset,
            "filters_applied":  {k: v for k, v in filters.items() if v},
            "load_stats":       stats_load,
            "total_urls":       len(urls),
            "auth": {
                "enabled":      header_jar is not None,
                "headers_dir":  (str(Path(args.headers_dir))
                                 if args.headers_dir
                                 else str(workspace / "headers")),
                "profiles":     (header_jar.profiles_loaded()
                                 if header_jar is not None else []),
                "cli_header_names": sorted(cli_headers.keys()),
                "no_auth_flag": args.no_auth,
            },
            "ai": {
                "requested":        args.ai,
                "usable_providers": usable_names,
                "provider_used":    ai_client.provider if (ai_client and ai_client.available()) else None,
                "model_used":       ai_client.model    if (ai_client and ai_client.available()) else None,
                "workers":          args.ai_workers,
                "skip_static":      args.ai_skip_static,
                "force":            args.ai_force,
            },
            "refresh":   args.refresh,
            "no_fetch":  args.no_fetch,
            "timestamp": now_iso(),
        })
    except Exception as e:
        log("failed to write import metadata: {}: {}".format(
            type(e).__name__, e), "warn")

    # ---- Fetch ---------------------------------------------------------
    section("FETCHING" if not args.no_fetch else "REGISTERING (no fetch)")
    if args.no_fetch:
        log("registering {} URLs without fetching".format(len(urls)), "info")
    else:
        log("fetching {} URLs (workers={}, delay={}s/host)".format(
            len(urls), args.workers, args.delay), "info")

    used_slugs = {}
    used_slugs_lock = threading.Lock()
    throttle = HostThrottle(args.delay)
    stats = FetchStats(total=len(urls))
    out_lock = threading.Lock()

    ai_results = []
    ai_results_lock = threading.Lock()

    t0 = time.time()

    def handle(url, status, outcome):
        if outcome == "skipped":
            return
        if outcome.startswith("error:"):
            if not args.quiet:
                log("  ✗ [{}] {}".format(outcome.split(":", 1)[1], url[:110]),
                    "warn")
        else:
            if not args.quiet:
                log("  [{}] {}".format(status, url[:110]), "ok",
                    urlparse(url).netloc)

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {}
            for u in urls:
                fut = pool.submit(
                    fetch_worker, u, workspace, used_slugs, used_slugs_lock,
                    throttle, header_jar, fallback_headers,
                    args.no_fetch, args.refresh,
                    ai_client, ai_semaphore, args.ai_force, args.ai_skip_static,
                    stats, out_lock, args.quiet,
                )
                futures[fut] = u

            done_count = 0
            for fut in as_completed(futures):
                url = futures[fut]
                done_count += 1
                try:
                    _, status, outcome = fut.result()
                except Exception as e:
                    stats.bump("failed")
                    stats.record_error("worker:{}".format(type(e).__name__))
                    if not args.quiet:
                        log("  ✗ worker crash for {}: {}: {}".format(
                            url[:80], type(e).__name__, e), "warn")
                    continue

                if outcome != "skipped" and outcome.startswith("error:"):
                    stats.bump("failed")
                handle(url, status, outcome)

                # Progress line
                if (done_count % PROGRESS_EVERY == 0
                        or done_count == len(urls)):
                    snap = stats.snapshot()
                    elapsed = time.time() - stats.started_at
                    rate = done_count / elapsed if elapsed > 0 else 0
                    eta = (len(urls) - done_count) / rate if rate > 0 else 0
                    log("progress {}/{}  ok={} fail={} skip={}  ~{:.0f}/s  ETA {}".format(
                        done_count, len(urls),
                        snap["written"], snap["failed"], snap["skipped"],
                        rate, format_duration(eta)), "info", "PROG")

                # Capture AI recon for index
                if ai_client is not None and ai_client.available():
                    try:
                        parsed = urlparse(url)
                        host = parsed.netloc.lower()
                        host_dir = workspace / "sites" / safe_filename(host)
                        # Try original slug, then any deduped variant
                        candidates = [slug_for_url(url)]
                        with used_slugs_lock:
                            for s, u2 in used_slugs.get(host, {}).items():
                                if u2 == url and s not in candidates:
                                    candidates.append(s)
                        for cand in candidates:
                            fpath = host_dir / "{}.json".format(cand)
                            if fpath.exists():
                                rec = load_json(fpath)
                                ar = rec.get("ai_recon")
                                if ar:
                                    ar2 = dict(ar)
                                    ar2["url"] = url
                                    with ai_results_lock:
                                        ai_results.append(ar2)
                                break
                    except Exception:
                        pass

    except KeyboardInterrupt:
        print()
        log("interrupted — partial workspace preserved", "warn")

    elapsed = time.time() - t0

    # ---- Summary --------------------------------------------------------
    snap = stats.snapshot()

    section("SUMMARY")
    log("workspace     : {}".format(workspace), "ok")
    log("unique hosts  : {}".format(
        len(set(urlparse(u).netloc for u in urls))), "info")
    log("pages written : {}".format(snap["written"]), "ok")
    if snap["skipped"]:
        log("pages skipped : {} (already existed)".format(snap["skipped"]), "info")
    if snap["refreshed"]:
        log("pages refreshed: {}".format(snap["refreshed"]), "info")
    if snap["failed"]:
        log("pages failed  : {}".format(snap["failed"]), "warn")
    if snap["authenticated"] or snap["unauthenticated"]:
        log("authenticated : {}  |  unauthenticated : {}".format(
            snap["authenticated"], snap["unauthenticated"]), "info")
    if snap["error_reasons"]:
        reasons = sorted(snap["error_reasons"].items(), key=lambda x: -x[1])
        log("error breakdown: " + "  ".join(
            "{}={}".format(r, n) for r, n in reasons[:6]), "info")
    log("elapsed       : {}".format(format_duration(elapsed)), "info")

    # AI summary
    if ai_client is not None and ai_client.available():
        print_ai_summary(stats, ai_client)

    # Priority index
    if ai_results:
        try:
            n = write_ai_index(workspace, ai_results)
            log("priority index: {} pages  ({})".format(
                n, workspace / "_ai_recon_index.json"), "ok")
        except Exception as e:
            log("failed to write priority index: {}: {}".format(
                type(e).__name__, e), "warn")

    # Final metadata merge
    try:
        final = load_json(workspace / "_burp_import.json")
    except Exception:
        final = {}
    final["final_stats"] = snap
    final["completed_at"] = now_iso()
    if ai_client is not None:
        final["ai"]["usage"] = dict(ai_client.stats)
    try:
        save_json(workspace / "_burp_import.json", final)
    except Exception:
        pass

    # Next steps
    print()
    print("{}Next steps:{}".format(C.D, C.R))
    print()
    if ai_results:
        print("  {}AI priority index:{} {}".format(
            C.CY, C.R, workspace / "_ai_recon_index.json"))
        print("  {}High-priority pages (scan these first):{}".format(C.D, C.R))
        for r in [x for x in ai_results if x.get("priority") == "high"][:5]:
            print("    · {} [{}]".format(
                r.get("url", "")[:80],
                ",".join(r.get("suggested_scanners", []))))
        print()

    print("  python3 sqli.py           {}".format(workspace))
    print("  python3 xss.py            {} --browser".format(workspace))
    print("  python3 ssrf.py           {}".format(workspace))
    print("  python3 open_redirect.py  {}".format(workspace))
    print("  python3 path_traversal.py {}".format(workspace))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn")
        sys.exit(130)
