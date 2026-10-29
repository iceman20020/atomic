"""
spine.py — the backbone of ATOMIC.

HTTP client, async pool, DNS resolvers, TLS inspection, finding schema,
target normalization, favicon hashing, response analysis, JS extraction,
HTML parsing, URL utilities, concurrency helpers, dedupe.

Every module in ATOMIC hooks in here.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional
from urllib.parse import (
    urlparse, urljoin, urlunparse, urlencode, parse_qs, parse_qsl, quote,
)

import httpx

try:
    import dns.resolver
    import dns.exception
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False

try:
    import mmh3
    _HAS_MMH3 = True
except Exception:
    _HAS_MMH3 = False

try:
    import tldextract
    _TLD = tldextract.TLDExtract(suffix_list_urls=())
    _HAS_TLD = True
except Exception:
    _HAS_TLD = False


# ═══════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════
DEFAULT_TIMEOUT = 15.0
LONG_TIMEOUT = 45.0

UA_DEFAULT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
UA_MOBILE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)
UA_SCANNER = "sqlmap/1.8.3#stable (https://sqlmap.org)"
UA_CURL = "curl/8.6.0"

INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

SPA_MARKERS = (
    "<div id=\"root\"></div>", "<div id=\"app\"></div>",
    "<div id=\"__next\"></div>", "window.__NEXT_DATA__",
    "window.__NUXT__", "ng-version=", "data-reactroot",
)


# ═══════════════════════════════════════════════════════════════════
# TIME
# ═══════════════════════════════════════════════════════════════════
def now() -> float:
    return time.monotonic()


from contextlib import asynccontextmanager

@asynccontextmanager
async def timed(label: str = ""):
    """Measure elapsed time around a block. Yields a mutable dict with 'elapsed'."""
    box = {"label": label, "start": now(), "elapsed": 0.0}
    try:
        yield box
    finally:
        box["elapsed"] = now() - box["start"]


# ═══════════════════════════════════════════════════════════════════
# FINDING SCHEMA
# ═══════════════════════════════════════════════════════════════════
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _sev_norm(s: str) -> str:
    v = (s or "info").lower().strip()
    return v if v in _SEV_RANK else "info"

def _short_hash(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()
    return h[:10]


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    url: str = ""
    evidence: str = ""
    extra: dict = field(default_factory=dict)
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)
    id: str = ""

    def __post_init__(self):
        self.severity = _sev_norm(self.severity)
        if not self.id:
            self.id = _short_hash(self.category, self.title, self.url or "")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
        )
        return d


def make_finding(
    category: str,
    title: str,
    severity: str,
    url: str = "",
    evidence: str = "",
    extra: Optional[dict] = None,
    remediation: str = "",
) -> Finding:
    return Finding(
        category=category,
        title=title,
        severity=severity,
        url=url,
        evidence=evidence or "",
        extra=extra or {},
        remediation=remediation or "",
    )


# ═══════════════════════════════════════════════════════════════════
# DEDUPE
# ═══════════════════════════════════════════════════════════════════
def dedupe(items: Iterable, key) -> list:
    seen = set()
    out = []
    for it in items:
        k = key(it)
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    keyed = {}
    for f in findings:
        k = (f.category, f.title, f.url or "", f.evidence[:120] if f.evidence else "")
        cur = keyed.get(k)
        if cur is None:
            keyed[k] = f
        else:
            # prefer the higher severity record
            if _SEV_RANK[f.severity] < _SEV_RANK[cur.severity]:
                keyed[k] = f
    out = list(keyed.values())
    out.sort(key=lambda f: (_SEV_RANK[f.severity], f.category, f.title))
    return out


# ═══════════════════════════════════════════════════════════════════
# TARGET NORMALIZATION
# ═══════════════════════════════════════════════════════════════════
def _root_domain(host: str) -> str:
    host = host.split(":")[0].lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _HAS_TLD:
        ex = _TLD(host)
        if ex.domain and ex.suffix:
            return f"{ex.domain}.{ex.suffix}"
    # heuristic: last two labels; three if last two are a known ccTLD pair
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    cc2 = {"co", "ac", "gov", "edu", "org", "net", "com"}
    if parts[-2] in cc2 and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalize_target(target: str) -> dict:
    t = (target or "").strip()
    if not t:
        raise ValueError("empty target")
    if "://" not in t:
        t = "https://" + t
    p = urlparse(t)
    host = p.hostname or ""
    if not host:
        raise ValueError(f"cannot parse host from {target!r}")
    scheme = p.scheme or "https"
    netloc = p.netloc or host
    base_url = f"{scheme}://{netloc}".rstrip("/")
    return {
        "input": target,
        "scheme": scheme,
        "host": host,
        "netloc": netloc,
        "base_url": base_url,
        "root_domain": _root_domain(host),
    }


# ═══════════════════════════════════════════════════════════════════
# URL UTILITIES
# ═══════════════════════════════════════════════════════════════════
def url_has_query(url: str) -> bool:
    return bool(urlparse(url).query)


def url_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def strip_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def url_with_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    replaced = False
    new_pairs = []
    for k, v in pairs:
        if k == param:
            new_pairs.append((k, value))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((param, value))
    q = urlencode(new_pairs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, q, p.fragment))


def same_domain(a: str, b: str, include_sub: bool = True) -> bool:
    try:
        ha = (urlparse(a).hostname or "").lower()
        hb = (urlparse(b).hostname or "").lower()
    except Exception:
        return False
    if not ha or not hb:
        return False
    if include_sub:
        return _root_domain(ha) == _root_domain(hb)
    return ha == hb


# ═══════════════════════════════════════════════════════════════════
# RESPONSE ANALYSIS
# ═══════════════════════════════════════════════════════════════════
def resp_len(resp) -> int:
    if resp is None:
        return 0
    try:
        return len(resp.content)
    except Exception:
        try:
            return len(resp.text or "")
        except Exception:
            return 0


def resp_text(resp, limit: Optional[int] = None) -> str:
    if resp is None:
        return ""
    try:
        t = resp.text
    except Exception:
        try:
            t = resp.content.decode("utf-8", "ignore")
        except Exception:
            t = ""
    if limit is not None and len(t) > limit:
        return t[:limit]
    return t


def resp_hash(resp) -> str:
    if resp is None:
        return ""
    try:
        body = resp.content[:200_000]
    except Exception:
        body = resp_text(resp, 200_000).encode("utf-8", "ignore")
    return hashlib.sha256(body).hexdigest()


def body_snippet(resp, length: int = 200) -> str:
    t = resp_text(resp)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:length]


def header_dict(resp) -> dict:
    if resp is None:
        return {}
    try:
        return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return {}


def is_interesting_status(code: int) -> bool:
    return code in INTERESTING_STATUS


def looks_like_spa_catchall(resp, baseline_hash: str, baseline_len: int) -> bool:
    if resp is None:
        return False
    if resp.status_code != 200:
        return False
    try:
        body = resp_text(resp, 20_000)
    except Exception:
        return False
    h = resp_hash(resp)
    ln = resp_len(resp)
    if baseline_hash and h == baseline_hash and abs(ln - baseline_len) < 40:
        return True
    for marker in SPA_MARKERS:
        if marker in body:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ═══════════════════════════════════════════════════════════════════
class HttpClient:
    """
    Async wrapper around httpx.AsyncClient. Never raises to caller —
    returns None on transport failure so phases keep moving.

    `verify` defaults to True; operator passes verify=False.
    Redirects default to follow=True; callers override per-request.
    """

    def __init__(self, verify: bool = True, concurrency: int = 60,
                 default_timeout: float = DEFAULT_TIMEOUT,
                 default_ua: str = UA_DEFAULT):
        self.verify = verify
        self.concurrency = concurrency
        self.default_timeout = default_timeout
        self.default_ua = default_ua
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        limits = httpx.Limits(
            max_connections=self.concurrency,
            max_keepalive_connections=max(10, self.concurrency // 2),
        )
        timeout = httpx.Timeout(self.default_timeout, connect=10.0)
        self._client = httpx.AsyncClient(
            verify=self.verify,
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": self.default_ua,
                     "Accept": "*/*",
                     "Accept-Language": "en-US,en;q=0.9"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[Any] = None,
        content: Optional[Any] = None,
        headers: Optional[dict] = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True,
    ):
        if self._client is None:
            raise RuntimeError("HttpClient not entered — use `async with`.")
        try:
            return await self._client.request(
                method,
                url,
                params=params,
                data=data,
                json=json,
                content=content,
                headers=headers,
                timeout=timeout if timeout is not None else self.default_timeout,
                follow_redirects=follow_redirects,
            )
        except Exception:
            return None

    async def get(self, url: str, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw):
        return await self.request("POST", url, **kw)


# ═══════════════════════════════════════════════════════════════════
# CONCURRENCY HELPERS
# ═══════════════════════════════════════════════════════════════════
async def gather_limited(coros, limit: int = 20) -> list:
    """Run coroutines with a concurrency ceiling. Never raises; failed
    coroutines yield None in place."""
    sem = asyncio.Semaphore(limit)

    async def _wrap(c):
        async with sem:
            try:
                return await c
            except Exception:
                return None

    return await asyncio.gather(*[_wrap(c) for c in coros])


async def map_limited(items: list, fn, limit: int = 20) -> list:
    coros = [fn(it) for it in items]
    return await gather_limited(coros, limit=limit)


# ═══════════════════════════════════════════════════════════════════
# DNS RESOLVER
# ═══════════════════════════════════════════════════════════════════
class DNSResolver:
    """
    Async DNS wrapper. Falls back to socket.getaddrinfo for A/AAAA when
    dnspython is unavailable; MX/TXT/CNAME/CAA/NS require dnspython.
    """

    def __init__(self, nameservers: Optional[list[str]] = None, timeout: float = 4.0):
        self.timeout = timeout
        if _HAS_DNS:
            self._resolver = dns.resolver.Resolver(configure=True)
            if nameservers:
                self._resolver.nameservers = nameservers
            self._resolver.timeout = timeout
            self._resolver.lifetime = timeout
        else:
            self._resolver = None

    def _q_sync(self, name: str, rtype: str) -> list[str]:
        if not self._resolver:
            return []
        try:
            answers = self._resolver.resolve(name, rtype, raise_on_no_answer=False)
            out = []
            for r in answers or []:
                out.append(str(r).rstrip("."))
            return out
        except Exception:
            return []

    async def async_query(self, name: str, rtype: str) -> list[str]:
        if self._resolver:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._q_sync, name, rtype)
        # fallback for A/AAAA
        if rtype in ("A", "AAAA"):
            return await self._socket_lookup(name, rtype)
        return []

    async def _socket_lookup(self, name: str, rtype: str) -> list[str]:
        loop = asyncio.get_event_loop()

        def _do():
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            try:
                infos = socket.getaddrinfo(name, None, fam)
                out = []
                for info in infos:
                    out.append(info[4][0])
                return sorted(set(out))
            except Exception:
                return []

        return await loop.run_in_executor(None, _do)

    def query(self, name: str, rtype: str) -> list[str]:
        """Synchronous query — used during WHOIS / phase_dns."""

        if self._resolver:
            return self._q_sync(name, rtype)
        if rtype in ("A", "AAAA"):
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            try:
                infos = socket.getaddrinfo(name, None, fam)
                return sorted({i[4][0] for i in infos})
            except Exception:
                return []
        return []

    async def async_reverse(self, ip: str) -> list[str]:
        if not self._resolver:
            loop = asyncio.get_event_loop()

            def _do():
                try:
                    host, _, _ = socket.gethostbyaddr(ip)
                    return [host]
                except Exception:
                    return []

            return await loop.run_in_executor(None, _do)

        try:
            rev = ipaddress.ip_address(ip).reverse_pointer
        except Exception:
            return []
        return await self.async_query(rev, "PTR")

    def bulk(self, root: str) -> dict:
        """Synchronous bulk fetch — matches phase_dns's expectations."""
        out = {}
        for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA"):
            try:
                vals = self.query(root, rtype)
            except Exception:
                vals = []
            if vals:
                out[rtype] = vals
        return out


# ═══════════════════════════════════════════════════════════════════
# TLS INSPECTION
# ═══════════════════════════════════════════════════════════════════
def ssl_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Pull peer certificate. Returns dict with subject, issuer, sans,
    not_before, not_after, serial, error."""
    out = {"subject": {}, "issuer": {}, "sans": [], "not_before": None,
           "not_after": None, "serial": None, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    out["serial"] = hashlib.sha256(der).hexdigest()[:32]
                cert = ssock.getpeercert()
                if cert:
                    out["subject"] = dict(x[0] for x in cert.get("subject", []))
                    out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    out["not_before"] = cert.get("notBefore")
                    out["not_after"] = cert.get("notAfter")
                    sans = []
                    for kind, val in cert.get("subjectAltName", []):
                        if kind.lower() == "dns":
                            sans.append(val)
                    out["sans"] = sans
    except Exception as e:
        out["error"] = str(e)
    return out


def ssl_supports(host: str, port: int, version, timeout: float = 4.0) -> bool:
    """Return True if TLS handshake succeeds with the given TLSVersion."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except Exception:
            pass
        try:
            ctx.options |= 0  # noop
        except Exception:
            pass
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════
# FAVICON
# ═══════════════════════════════════════════════════════════════════
async def fetch_favicon(client: HttpClient, base_url: str) -> dict:
    """Fetch favicon. Returns {url, status, len, sha256, mmh3}."""
    result = {"url": "", "status": None, "len": 0, "sha256": None, "mmh3": None}
    candidates = [
        base_url.rstrip("/") + "/favicon.ico",
    ]
    # try to discover via <link rel="icon"> on root page
    try:
        r = await client.get(base_url)
        if r is not None and r.status_code == 200:
            body = resp_text(r, 50_000)
            for m in re.finditer(
                r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]+href=["\']([^"\']+)["\']',
                body, re.I,
            ):
                href = m.group(1).strip()
                candidates.insert(0, urljoin(base_url, href))
                break
    except Exception:
        pass

    for url in candidates:
        r = await client.get(url)
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.content
        except Exception:
            continue
        if not data:
            continue
        result["url"] = url
        result["status"] = r.status_code
        result["len"] = len(data)
        result["sha256"] = hashlib.sha256(data).hexdigest()
        if _HAS_MMH3:
            try:
                result["mmh3"] = mmh3.hash(
                    base64.encodebytes(data).decode()
                )
            except Exception:
                pass
        return result
    return result


def favicon_hash_bytes(data: bytes) -> dict:
    out = {"sha256": hashlib.sha256(data).hexdigest(), "mmh3": None}
    if _HAS_MMH3:
        try:
            out["mmh3"] = mmh3.hash(base64.encodebytes(data).decode())
        except Exception:
            pass
    return out


# ═══════════════════════════════════════════════════════════════════
# HTML PARSING (regex-based, no bs4)
# ═══════════════════════════════════════════════════════════════════
def parse_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def parse_comments(html: str) -> list[str]:
    if not html:
        return []
    out = []
    for m in re.finditer(r"<!--(.*?)-->", html, re.S):
        c = re.sub(r"\s+", " ", m.group(1)).strip()
        if c:
            out.append(c[:500])
    return out


def parse_metas(html: str) -> dict:
    out = {}
    if not html:
        return out
    for m in re.finditer(r"<meta\s+([^>]+?)/?>", html, re.I):
        attrs = m.group(1)
        name_m = re.search(r'name=["\']([^"\']+)["\']', attrs, re.I)
        content_m = re.search(r'content=["\']([^"\']*)["\']', attrs, re.I)
        prop_m = re.search(r'property=["\']([^"\']+)["\']', attrs, re.I)
        key = (name_m.group(1) if name_m else
               (prop_m.group(1) if prop_m else None))
        if key:
            out[key.lower()] = (content_m.group(1) if content_m else "")[:300]
    return out


def parse_scripts(html: str, base_url: str) -> list[str]:
    if not html:
        return []
    out = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        out.add(urljoin(base_url, m.group(1).strip()))
    return sorted(out)


def parse_links(html: str, base_url: str) -> list[str]:
    if not html:
        return []
    out = set()
    for m in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.I):
        href = m.group(1).strip()
        if href.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        out.add(urljoin(base_url, href))
    return sorted(out)


def parse_forms(html: str) -> list[dict]:
    """Return [{action, method, inputs:[{name,type,value,required}]}]."""
    if not html:
        return []
    forms = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'method=["\']([^"\']+)["\']', attrs, re.I)
        inputs = []
        for im in re.finditer(r"<input\b([^>]+?)/?>", inner, re.I):
            ia = im.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', ia, re.I)
            type_m = re.search(r'type=["\']([^"\']+)["\']', ia, re.I)
            val_m = re.search(r'value=["\']([^"\']*)["\']', ia, re.I)
            req = bool(re.search(r"\brequired\b", ia, re.I))
            if not name_m:
                continue
            inputs.append({
                "name": name_m.group(1),
                "type": (type_m.group(1) if type_m else "text").lower(),
                "value": val_m.group(1) if val_m else "",
                "required": req,
            })
        for sm in re.finditer(r"<select\b([^>]*)>(.*?)</select>", inner, re.I | re.S):
            sa = sm.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', sa, re.I)
            if name_m:
                inputs.append({"name": name_m.group(1), "type": "select",
                               "value": "", "required": False})
        for tm in re.finditer(r"<textarea\b([^>]*)>(.*?)</textarea>", inner, re.I | re.S):
            ta = tm.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', ta, re.I)
            if name_m:
                inputs.append({"name": name_m.group(1), "type": "textarea",
                               "value": tm.group(2)[:200], "required": False})
        forms.append({
            "action": (action_m.group(1) if action_m else ""),
            "method": (method_m.group(1) if method_m else "GET").upper(),
            "inputs": inputs,
        })
    return forms


# ═══════════════════════════════════════════════════════════════════
# JS ARTIFACT EXTRACTION
# ═══════════════════════════════════════════════════════════════════
_JS_ENDPOINT_RE = re.compile(
    r"""["'`](/[\w\-./?=&%#{}\[\]]{2,200}|https?://[^\s"'`<>]{6,300})["'`]"""
)
_JS_WS_RE = re.compile(r"""["'`](wss?://[^\s"'`<>]+)["'`]""")
_JS_STORAGE_RE = re.compile(
    r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\(\s*["'`]([^"'`]+)["'`]"""
)
_JS_ONCLICK_RE = re.compile(
    r"""\.on\(["'`]click["'`]|addEventListener\(["'`]click["'`]"""
)
_JS_DATASET_RE = re.compile(r"""data-([\w\-]+)=""")
_JS_SOURCEMAP_RE = re.compile(r"""sourceMappingURL=([^\s"'`]+)""")


def extract_js_artifacts(js: str, source: str = "") -> dict:
    """Return dict of extracted artifacts from a JS blob."""
    out = {
        "source": source,
        "endpoints": [],
        "websockets": [],
        "storage_keys": [],
        "onclick_handlers": 0,
        "data_attrs": [],
        "sourcemaps": [],
    }
    if not js:
        return out
    ep_set = set()
    for m in _JS_ENDPOINT_RE.finditer(js):
        cand = m.group(1)
        # skip obvious junk
        if len(cand) < 3 or cand.startswith("//"):
            continue
        ep_set.add(cand)
    out["endpoints"] = sorted(ep_set)[:300]

    out["websockets"] = sorted({m.group(1) for m in _JS_WS_RE.finditer(js)})[:50]
    out["storage_keys"] = sorted({m.group(1) for m in _JS_STORAGE_RE.finditer(js)})[:50]
    out["onclick_handlers"] = len(_JS_ONCLICK_RE.findall(js))
    out["data_attrs"] = sorted({m.group(1) for m in _JS_DATASET_RE.finditer(js)})[:80]
    out["sourcemaps"] = sorted({m.group(1) for m in _JS_SOURCEMAP_RE.finditer(js)})[:20]
    return out


# ═══════════════════════════════════════════════════════════════════
# REEXPORTS
# ═══════════════════════════════════════════════════════════════════
__all__ = [
    # constants
    "DEFAULT_TIMEOUT", "LONG_TIMEOUT",
    "UA_DEFAULT", "UA_MOBILE", "UA_SCANNER", "UA_CURL",
    "INTERESTING_STATUS",
    # time
    "now", "timed",
    # findings
    "Finding", "make_finding",
    # dedupe
    "dedupe", "dedupe_findings",
    # target
    "normalize_target",
    # url helpers
    "url_has_query", "url_params", "strip_query", "url_with_param",
    "same_domain", "urljoin", "urlparse", "urlencode", "parse_qs",
    # response
    "resp_len", "resp_text", "resp_hash", "body_snippet", "header_dict",
    "is_interesting_status", "looks_like_spa_catchall",
    # client
    "HttpClient",
    # concurrency
    "gather_limited", "map_limited",
    # dns
    "DNSResolver",
    # tls
    "ssl_cert", "ssl_supports",
    # favicon
    "fetch_favicon", "favicon_hash_bytes",
    # parsers
    "parse_title", "parse_comments", "parse_metas",
    "parse_scripts", "parse_links", "parse_forms",
    "extract_js_artifacts",
]
