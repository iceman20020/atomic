"""
specter.py — passive and semi-active reconnaissance.

Every phase returns (findings: list[Finding], data: dict). The orchestrator
runs phases in sequence, accumulating findings and data. Active probes here
are single-request, safe, observable as normal web traffic.
"""
from __future__ import annotations
import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import struct
import time
from urllib.parse import urlparse, urljoin, urlunparse, urlencode, parse_qs, quote

from .spine import (
    HttpClient, Finding, make_finding, normalize_target,
    resp_len, resp_text, resp_hash, body_snippet, header_dict,
    is_interesting_status, looks_like_spa_catchall,
    DNSResolver, ssl_cert, ssl_supports, fetch_favicon, favicon_hash_bytes,
    parse_title, parse_comments, parse_forms, parse_scripts, parse_links,
    parse_metas, extract_js_artifacts,
    url_with_param, url_params, url_has_query, strip_query, same_domain,
    dedupe, dedupe_findings, gather_limited, map_limited, timed,
    UA_DEFAULT, UA_MOBILE, UA_SCANNER, UA_CURL,
    DEFAULT_TIMEOUT, LONG_TIMEOUT,
)
from .armory import (
    COMMON_SUBS, COMMON_DIRS, HIDDEN_FILES, COMMON_PARAM_NAMES,
    BACKUP_SUFFIXES, INTERESTING_DIR_WORDS,
    TAKEOVER_FINGERPRINTS, SECRET_PATTERNS, WAF_HEADER_FINGERPRINTS,
    WAF_COOKIE_FINGERPRINTS, WAF_BLOCK_MARKERS, WAF_PROBE_PAYLOADS,
    DATABASE_UI_PATHS, DATABASE_SUCCESS_MARKERS,
    TECH_SIGNATURES_BODY, TECH_VERSION_EXTRACTORS,
    CLOUD_HEADER_SIGNATURES, API_PATHS, COMMON_PORTS, PORT_BANNERS,
    WEBSHELL_MARKERS, HTTP_METHODS_ALL, EVIL_ORIGINS,
)


# ═══════════════════════════════════════════════════════════════════
# PHASE 1 — DNS + WHOIS + TLS
# ═══════════════════════════════════════════════════════════════════
async def phase_dns(target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"records": {}, "spf": None, "dmarc": None, "dkim_hints": [], "mx": [], "reverse": {}}
    root = target["root_domain"]
    resolver = DNSResolver()

    # bulk record fetch
    data["records"] = resolver.bulk(root)

    # SPF
    for txt in data["records"].get("TXT", []):
        if txt.lower().startswith("v=spf1"):
            data["spf"] = txt
            if "-all" not in txt and "~all" not in txt:
                findings.append(make_finding(
                    "dns", "SPF record permissive", "low",
                    url=root,
                    evidence=f"SPF: {txt[:200]} — missing hardfail (-all)",
                    remediation="Change SPF tail to -all after verification.",
                ))
            break

    # DMARC
    dmarc = resolver.query(f"_dmarc.{root}", "TXT")
    if dmarc:
        data["dmarc"] = dmarc[0]
        if "p=none" in dmarc[0]:
            findings.append(make_finding(
                "dns", "DMARC policy is p=none", "low",
                url=root,
                evidence=dmarc[0][:200],
                remediation="Move DMARC policy to quarantine or reject.",
            ))
    else:
        findings.append(make_finding(
            "dns", "DMARC record missing", "medium",
            url=root,
            evidence=f"_dmarc.{root} returned no TXT record",
            remediation="Publish a DMARC record with p=quarantine.",
        ))

    # DKIM selectors
    for sel in ("default", "google", "mail", "s1", "s2", "k1", "dkim",
                "selector1", "selector2", "mailchimp", "mandrill", "sendgrid"):
        vals = resolver.query(f"{sel}._domainkey.{root}", "TXT")
        if vals:
            data["dkim_hints"].append({"selector": sel, "record": vals[0][:200]})

    # MX
    data["mx"] = data["records"].get("MX", [])

    # reverse of A records
    for ip in data["records"].get("A", []):
        rev = await resolver.async_reverse(ip)
        if rev:
            data["reverse"][ip] = rev
            if any("shared" in h.lower() or "hosting" in h.lower() for h in rev):
                findings.append(make_finding(
                    "dns", "Shared hosting detected", "info",
                    url=root, evidence=f"{ip} → {', '.join(rev)[:120]}",
                ))

    # CAA
    if not data["records"].get("CAA"):
        findings.append(make_finding(
            "dns", "CAA record missing", "low",
            url=root,
            evidence="No CAA record; any CA can issue certificates.",
            remediation="Publish CAA record listing authorized CAs.",
        ))

    return findings, data


async def phase_whois(target: dict) -> tuple[list[Finding], dict]:
    """Bare minimal WHOIS-over-port-43."""
    findings: list[Finding] = []
    data: dict = {"server": None, "summary": {}, "raw_head": ""}
    root = target["root_domain"]
    tld = root.split(".")[-1]

    def _whois(host: str, q: str, timeout: float = 8.0) -> str:
        try:
            with socket.create_connection((host, 43), timeout=timeout) as s:
                s.sendall((q + "\r\n").encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 65536:
                        break
                return buf.decode(errors="ignore")
        except Exception:
            return ""

    loop = asyncio.get_event_loop()
    iana = await loop.run_in_executor(None, _whois, "whois.iana.org", tld)
    m = re.search(r"whois:\s*(\S+)", iana or "")
    server = m.group(1) if m else "whois.verisign-grs.com"
    data["server"] = server

    raw = await loop.run_in_executor(None, _whois, server, "=" + root if "verisign" in server else root)
    data["raw_head"] = raw[:3000]

    for line in raw.splitlines():
        if ":" in line and not line.startswith("%"):
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k and v and k not in data["summary"]:
                data["summary"][k] = v

    # flag expired domain (unlikely for real target but informative)
    exp = data["summary"].get("registry expiry date") or data["summary"].get("expiry date")
    if exp:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(exp)
            days = (dt - __import__("datetime").datetime.now(dt.tzinfo)).days
            if days < 30:
                findings.append(make_finding(
                    "whois", "Domain expires soon", "medium",
                    url=root, evidence=f"Expiry: {exp} ({days} days)",
                ))
        except Exception:
            pass
    return findings, data


async def phase_tls(target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"cert": {}, "protocols": {}}

    host = target["host"]
    port = 443
    loop = asyncio.get_event_loop()
    cert = await loop.run_in_executor(None, ssl_cert, host, port)
    data["cert"] = cert

    if cert.get("error"):
        findings.append(make_finding(
            "tls", "TLS handshake error", "medium",
            url=f"https://{host}:{port}",
            evidence=cert["error"][:200],
        ))
        return findings, data

    # supported protocol versions
    for name, ver in (("tls1.0", ssl.TLSVersion.TLSv1),
                      ("tls1.1", ssl.TLSVersion.TLSv1_1),
                      ("tls1.2", ssl.TLSVersion.TLSv1_2),
                      ("tls1.3", ssl.TLSVersion.TLSv1_3)):
        ok = await loop.run_in_executor(None, ssl_supports, host, port, ver)
        data["protocols"][name] = ok
        if ok and name in ("tls1.0", "tls1.1"):
            findings.append(make_finding(
                "tls", f"{name.upper()} supported", "medium",
                url=f"https://{host}:{port}",
                evidence=f"{name} negotiated — deprecated protocol still accepted.",
                remediation="Disable TLS 1.0 and 1.1.",
            ))

    # SAN subdomains
    if cert.get("sans"):
        pass  # used by subdomain phase

    # expiry
    if cert.get("not_after"):
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(cert["not_after"])
            days = (dt - __import__("datetime").datetime.now(dt.tzinfo)).days
            if days < 0:
                findings.append(make_finding(
                    "tls", "Certificate expired", "medium",
                    url=f"https://{host}:{port}",
                    evidence=f"Expired {abs(days)} days ago ({cert['not_after']}).",
                ))
            elif days < 14:
                findings.append(make_finding(
                    "tls", "Certificate expiring soon", "low",
                    url=f"https://{host}:{port}",
                    evidence=f"Expires in {days} days ({cert['not_after']}).",
                ))
        except Exception:
            pass
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 2 — FINGERPRINT
# ═══════════════════════════════════════════════════════════════════
async def phase_fingerprint(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"status": None, "title": "", "tech": [], "tech_versions": {},
                  "headers": {}, "favicon": {}, "cloud": [], "meta": {}, "comments": []}

    base = target["base_url"]
    r = await client.get(base)
    if r is None:
        return findings, data
    data["status"] = r.status_code
    body = resp_text(r)
    headers = header_dict(r)
    data["headers"] = headers
    data["title"] = parse_title(body)
    data["comments"] = parse_comments(body)
    data["meta"] = parse_metas(body)

    # body-based tech fingerprint
    for name, patterns in TECH_SIGNATURES_BODY.items():
        for pat in patterns:
            if re.search(pat, body, re.I):
                data["tech"].append(name)
                break

    # header-based
    for hdr in ("server", "x-powered-by", "x-generator"):
        v = headers.get(hdr, "")
        for name, pats in TECH_SIGNATURES_BODY.items():
            for pat in pats:
                if re.search(pat, v, re.I):
                    data["tech"].append(name)

    # version extractors
    for tech, patterns in TECH_VERSION_EXTRACTORS.items():
        for pat, group in patterns:
            m = re.search(pat, body + "\n" + str(headers), re.I)
            if m:
                data["tech_versions"][tech] = m.group(group)[:30] if m.groups() else m.group(0)[:30]
                break

    # cloud provider sniff
    hdrs_flat = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    for provider, sigs in CLOUD_HEADER_SIGNATURES.items():
        for s in sigs:
            if s.lower() in hdrs_flat:
                data["cloud"].append(provider)
                break

    # favicon
    data["favicon"] = await fetch_favicon(client, base)

    # interesting header leaks
    if "server" in headers:
        srv = headers["server"]
        if any(c.isdigit() for c in srv) and len(srv) < 60:
            findings.append(make_finding(
                "info", "Server version disclosed", "info",
                url=base, evidence=f"Server: {srv}",
                remediation="Suppress version from Server header.",
            ))
    if "x-powered-by" in headers:
        findings.append(make_finding(
            "info", "Technology disclosed via X-Powered-By", "info",
            url=base, evidence=f"X-Powered-By: {headers['x-powered-by']}",
            remediation="Remove X-Powered-By header.",
        ))

    # HTML comments — check for suspicious content
    for c in data["comments"]:
        lc = c.lower()
        if any(k in lc for k in ("password", "todo", "fixme", "hack", "temp", "admin", "debug",
                                  "internal", "secret", "key", "api_key", "deprecated")):
            findings.append(make_finding(
                "info", "Suspicious HTML comment", "low",
                url=base, evidence=c[:300],
                remediation="Remove developer comments from production HTML.",
            ))

    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 3 — WAF
# ═══════════════════════════════════════════════════════════════════
async def phase_waf(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"vendors": [], "block_page": False, "probe_matrix": {}, "ruleset_guess": None}

    base = target["base_url"]
    # passive: header + cookie fingerprint
    r = await client.get(base)
    if r is None:
        return findings, data
    headers = header_dict(r)
    cookie_header = " ".join(r.headers.get_list("set-cookie")).lower()

    for vendor, sigs in WAF_HEADER_FINGERPRINTS.items():
        for s in sigs:
            if s in headers or s in str(headers).lower():
                if vendor not in data["vendors"]:
                    data["vendors"].append(vendor)
                break

    for vendor, sigs in WAF_COOKIE_FINGERPRINTS.items():
        for s in sigs:
            if s in cookie_header:
                if vendor not in data["vendors"]:
                    data["vendors"].append(vendor)
                break

    # active probe matrix — one request per (attack, vector)
    base_stripped = base.rstrip("/")
    baseline = await client.get(base_stripped + "/__atomic_probe__")
    baseline_hash = resp_hash(baseline) if baseline else ""
    baseline_len = resp_len(baseline) if baseline else 0

    async def _probe(attack: str, payload: str, vector: str = "query"):
        if vector == "query":
            url = base_stripped + "/?atomic_test=" + quote(payload)
            r = await client.get(url, headers={"User-Agent": UA_DEFAULT})
        elif vector == "header":
            r = await client.get(base, headers={"User-Agent": UA_DEFAULT, "X-Atomic-Test": payload})
        elif vector == "body":
            r = await client.post(base, data={"atomic_test": payload},
                                  headers={"User-Agent": UA_DEFAULT,
                                           "Content-Type": "application/x-www-form-urlencoded"})
        elif vector == "cookie":
            r = await client.get(base, headers={"User-Agent": UA_DEFAULT,
                                                "Cookie": f"atomic_test={quote(payload)}"})
        elif vector == "scanner":
            r = await client.get(base, headers={"User-Agent": payload})
        else:
            return None
        return r

    probes = []
    for attack, payload in WAF_PROBE_PAYLOADS.items():
        if attack == "scanner_ua":
            probes.append((attack, UA_SCANNER, "scanner"))
            continue
        for vec in ("query", "header", "body", "cookie"):
            probes.append((attack, payload, vec))

    async def _run(probe):
        attack, payload, vec = probe
        r = await _probe(attack, payload, vec)
        if r is None:
            return attack, vec, None
        body = resp_text(r)
        blocked = False
        # detect by status
        if r.status_code in (403, 406, 419, 429, 501, 999):
            blocked = True
        # detect by body marker
        if not blocked:
            bl = body.lower()
            for marker in WAF_BLOCK_MARKERS:
                if marker in bl:
                    blocked = True
                    break
        # detect by body change (page differs from baseline a lot)
        if not blocked and r.status_code == 200:
            if abs(resp_len(r) - baseline_len) > 800 or resp_hash(r) != baseline_hash:
                # could be normal variation or normal app logic — call it "unclear"
                pass
        return attack, vec, {"status": r.status_code, "blocked": blocked,
                             "len": resp_len(r)}

    results = await gather_limited([_run(p) for p in probes], limit=20)

    matrix: dict[str, dict[str, str]] = {}
    for res in results:
        if not res:
            continue
        attack, vec, info = res
        if info is None:
            continue
        matrix.setdefault(attack, {})[vec] = (
            "blocked" if info["blocked"] else
            ("allow" if info["status"] == 200 else f"status:{info['status']}")
        )
    data["probe_matrix"] = matrix

    # gaps = attack classes where a vector is allowed
    gaps = []
    for attack, vecs in matrix.items():
        for vec, disp in vecs.items():
            if disp == "allow":
                gaps.append(f"{attack}@{vec}")
    if gaps:
        findings.append(make_finding(
            "waf", "WAF coverage gap detected", "medium",
            url=base,
            evidence=f"Unblocked vectors: {', '.join(gaps[:12])}",
            extra={"matrix": matrix},
            remediation="Extend WAF rules to cover these vectors.",
        ))

    if data["vendors"]:
        findings.append(make_finding(
            "info", f"WAF detected: {', '.join(data['vendors'])}", "info",
            url=base, evidence=f"Headers/cookies matched: {data['vendors']}",
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 4 — SECURITY HEADERS / CORS / METHODS / HOST HEADER
# ═══════════════════════════════════════════════════════════════════
SEC_HEADERS = {
    "strict-transport-security": ("medium", "HSTS missing — HTTPS downgrade possible"),
    "content-security-policy":    ("medium", "CSP missing — XSS has no browser-side mitigation"),
    "x-frame-options":            ("medium", "X-Frame-Options missing — clickjacking possible"),
    "x-content-type-options":     ("low",    "X-Content-Type-Options missing — MIME sniffing possible"),
    "referrer-policy":            ("low",    "Referrer-Policy missing — URL leakage possible"),
    "permissions-policy":         ("low",    "Permissions-Policy missing — feature access unrestricted"),
    "cross-origin-opener-policy": ("low",    "COOP missing — cross-origin window interaction possible"),
    "cross-origin-resource-policy": ("low",  "CORP missing — resource loading unrestricted"),
}

async def phase_headers(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"missing": {}, "present": {}, "leaky": {}, "cookies": [], "csp": None}
    base = target["base_url"]
    r = await client.get(base)
    if r is None:
        return findings, data
    h = header_dict(r)

    for name, (sev, msg) in SEC_HEADERS.items():
        if name not in h:
            data["missing"][name] = msg
            findings.append(make_finding(
                "headers", msg.split(" — ")[0], sev,
                url=base, evidence=f"Missing header: {name}",
                remediation=f"Add {name} header.",
            ))
        else:
            data["present"][name] = h[name][:200]

    for leak in ("server", "x-powered-by", "x-aspnet-version",
                 "x-aspnetmvc-version", "x-generator", "via"):
        if leak in h:
            data["leaky"][leak] = h[leak][:200]

    for sc in r.headers.get_list("set-cookie"):
        lc = sc.lower()
        flags = {
            "secure": "secure" in lc,
            "httponly": "httponly" in lc,
            "samesite": "samesite" in lc,
            "samesite_value": "strict" if "samesite=strict" in lc else
                              ("lax" if "samesite=lax" in lc else
                               ("none" if "samesite=none" in lc else None)),
        }
        data["cookies"].append({"raw": sc[:200], "flags": flags})
        missing = [f for f in ("secure", "httponly") if not flags[f]]
        if missing:
            findings.append(make_finding(
                "headers", f"Cookie missing {', '.join(missing)}", "medium",
                url=base, evidence=sc[:200],
                remediation="Set Secure and HttpOnly on all session cookies.",
            ))

    # CSP parse
    if "content-security-policy" in h:
        csp = h["content-security-policy"]
        data["csp"] = csp
        if "unsafe-inline" in csp:
            findings.append(make_finding(
                "headers", "CSP allows unsafe-inline", "low",
                url=base, evidence=csp[:300],
                remediation="Remove 'unsafe-inline' from CSP.",
            ))
        if "unsafe-eval" in csp:
            findings.append(make_finding(
                "headers", "CSP allows unsafe-eval", "low",
                url=base, evidence=csp[:300],
            ))
    return findings, data


async def phase_cors(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"issues": []}
    base = target["base_url"]
    for origin in EVIL_ORIGINS:
        r = await client.get(base, headers={"Origin": origin})
        if r is None:
            continue
        h = header_dict(r)
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"
        if not acao:
            continue
        issue = None
        if acao == "*" and acac:
            issue = ("high", "Wildcard origin with credentials")
        elif acao == origin and acac:
            issue = ("high", "Reflected origin with credentials")
        elif acao == origin:
            issue = ("low", "Reflected origin (no credentials)")
        elif origin in acao:
            issue = ("medium", "Origin substring reflected")
        if issue:
            sev, title = issue
            data["issues"].append({"severity": sev, "origin": origin,
                                   "acao": acao, "acac": acac, "reason": title})
            findings.append(make_finding(
                "cors", f"CORS misconfiguration: {title}", sev,
                url=base,
                evidence=f"Origin: {origin} → ACAO: {acao} · ACAC: {acac}",
                extra={"origin": origin, "acao": acao, "acac": acac},
                remediation="Whitelist origins; never combine wildcard with credentials.",
            ))
    return findings, data


async def phase_host_header(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"issues": []}
    base = target["base_url"]
    baseline = await client.get(base)
    if baseline is None:
        return findings, data
    base_len = resp_len(baseline)
    for hh in ("evil.example", "127.0.0.1", "localhost",
               "internal", f"{target['host']}.evil.example"):
        for header in ("X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-HTTP-Host-Override"):
            r = await client.get(base, headers={header: hh})
            if r is None or r.status_code >= 500:
                continue
            body = resp_text(r)
            if hh in body:
                issue = {"header": header, "value": hh,
                         "evidence": "reflected in body", "status": r.status_code}
                data["issues"].append(issue)
                findings.append(make_finding(
                    "host_header", f"{header} injection", "medium",
                    url=base, evidence=f"{header}: {hh} reflected in body",
                    remediation="Validate Host header against allow-list.",
                ))
                break
            if abs(resp_len(r) - base_len) > 500:
                issue = {"header": header, "value": hh,
                         "evidence": "significant body change", "status": r.status_code}
                data["issues"].append(issue)
                findings.append(make_finding(
                    "host_header", f"{header} changes response", "low",
                    url=base, evidence=f"{header}: {hh} → different body length",
                ))
                break
    return findings, data


async def phase_methods(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"allowed": {}, "trace": False, "put": False}
    base = target["base_url"]
    for m in HTTP_METHODS_ALL:
        if m == "CONNECT":
            continue
        r = await client.request(m, base)
        if r is None:
            continue
        data["allowed"][m] = r.status_code
    if data["allowed"].get("TRACE") == 200:
        data["trace"] = True
        findings.append(make_finding(
            "methods", "TRACE method enabled", "low",
            url=base, evidence="TRACE returned 200",
            remediation="Disable TRACE.",
        ))
    if data["allowed"].get("PUT") in (200, 201, 204):
        data["put"] = True
        findings.append(make_finding(
            "methods", "PUT method accepted", "medium",
            url=base, evidence="PUT returned success",
            remediation="Disable PUT if not needed.",
        ))
    if data["allowed"].get("DELETE") in (200, 204):
        findings.append(make_finding(
            "methods", "DELETE method accepted", "medium",
            url=base, evidence="DELETE returned success",
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 5 — SUBDOMAINS
# ═══════════════════════════════════════════════════════════════════
async def _subs_crtsh(client: HttpClient, root: str) -> set[str]:
    out = set()
    r = await client.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=30)
    if r and r.status_code == 200:
        try:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    n = name.strip().lower().lstrip("*.")
                    if n.endswith(root) and n != root:
                        out.add(n)
        except Exception:
            pass
    return out


async def _subs_hackertarget(client: HttpClient, root: str) -> set[str]:
    out = set()
    r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={root}", timeout=20)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if "," in line:
                host = line.split(",")[0].strip().lower()
                if host.endswith(root) and host != root:
                    out.add(host)
    return out


async def _subs_otx(client: HttpClient, root: str) -> set[str]:
    out = set()
    r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{root}/passive_dns", timeout=20)
    if r and r.status_code == 200:
        try:
            for e in r.json().get("passive_dns", []):
                h = e.get("hostname", "").lower().lstrip("*.")
                if h.endswith(root) and h != root:
                    out.add(h)
        except Exception:
            pass
    return out


async def _subs_rapiddns(client: HttpClient, root: str) -> set[str]:
    out = set()
    r = await client.get(f"https://rapiddns.io/subdomain/{root}?full=1", timeout=20)
    if r and r.status_code == 200:
        for m in re.finditer(r"<td>([\w.\-]+\." + re.escape(root) + r")</td>", r.text):
            h = m.group(1).lower()
            if h != root:
                out.add(h)
    return out


async def _subs_wordlist(client: HttpClient, root: str) -> set[str]:
    """Resolve each wordlist prefix."""
    resolver = DNSResolver()

    async def _check(prefix: str):
        host = f"{prefix}.{root}"
        a = await resolver.async_query(host, "A")
        if a:
            return host
        return None

    results = await gather_limited([_check(p) for p in COMMON_SUBS], limit=40)
    return {r for r in results if r}


async def phase_subdomains(client: HttpClient, target: dict, tls_data: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"count": 0, "subdomains": [], "sources": {}, "dangling": []}
    root = target["root_domain"]

    results = await asyncio.gather(
        _subs_crtsh(client, root),
        _subs_hackertarget(client, root),
        _subs_otx(client, root),
        _subs_rapiddns(client, root),
        _subs_wordlist(client, root),
        return_exceptions=True,
    )
    names = ("crt.sh", "hackertarget", "otx", "rapiddns", "wordlist")
    merged: set[str] = set()
    for name, r in zip(names, results):
        if isinstance(r, set):
            data["sources"][name] = len(r)
            merged |= r

    # add SANs from TLS
    if tls_data.get("cert", {}).get("sans"):
        for san in tls_data["cert"]["sans"]:
            san = san.lower().lstrip("*.")
            if san.endswith(root) and san != root:
                merged.add(san)
                data["sources"]["tls_san"] = data["sources"].get("tls_san", 0) + 1

    data["subdomains"] = sorted(merged)
    data["count"] = len(merged)
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 6 — PORTS
# ═══════════════════════════════════════════════════════════════════
async def _check_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool, str]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(200), timeout=1.0)
            banner = data.decode("utf-8", "ignore").strip()[:80]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True, banner
    except Exception:
        return port, False, ""


async def phase_ports(target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"open": [], "banners": {}}
    host = target["host"]

    # skip if IP not resolvable
    results = await gather_limited(
        [_check_port(host, p) for p in COMMON_PORTS], limit=60,
    )

    for res in results:
        if not res:
            continue
        port, is_open, banner = res
        if is_open:
            data["open"].append(port)
            data["banners"][port] = banner
            svc = PORT_BANNERS.get(port, "unknown")
            sev = "info"
            if port in (21, 23, 445, 3389, 5900):
                sev = "medium"
            if port in (1433, 3306, 5432, 6379, 9200, 27017, 11211):
                sev = "high"
            findings.append(make_finding(
                "port", f"Port {port} open ({svc})", sev,
                url=f"{host}:{port}",
                evidence=f"TCP connect OK · banner: {banner[:60] or 'none'}",
                extra={"port": port, "service": svc},
            ))
    data["open"] = sorted(data["open"])
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 7 — WAYBACK
# ═══════════════════════════════════════════════════════════════════
async def phase_wayback(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"count": 0, "urls": [], "params": [], "sensitive": []}
    root = target["root_domain"]

    r = await client.get(
        f"http://web.archive.org/cdx/search/cdx?url=*.{root}/*&output=json"
        f"&fl=original,timestamp,statuscode&collapse=urlkey&limit=3000",
        timeout=45,
    )
    if not r or r.status_code != 200:
        return findings, data
    try:
        rows = r.json()
    except Exception:
        return findings, data

    urls = []
    params = set()
    sensitive = []
    for row in rows[1:]:
        if not row:
            continue
        u = row[0]
        urls.append(u)
        if "?" in u and "=" in u:
            for pair in u.split("?", 1)[1].split("&"):
                if "=" in pair:
                    params.add(pair.split("=", 1)[0])
        # interesting historical URLs
        lu = u.lower()
        for marker in ("/admin", "/api/", "/backup", "/.env", "/.git", "/config",
                       "/internal", "/private", ".sql", ".zip", ".bak", "/debug"):
            if marker in lu:
                sensitive.append(u)
                break

    data["count"] = len(urls)
    data["urls"] = urls[:2000]
    data["params"] = sorted(params)[:300]
    data["sensitive"] = sensitive[:100]
    if sensitive:
        findings.append(make_finding(
            "wayback", f"{len(sensitive)} sensitive historical URL(s)", "low",
            url=f"*.{root}",
            evidence="\n".join(sensitive[:10]),
            remediation="Remove obsolete resources from origin server.",
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 8 — DIRECTORIES + HIDDEN FILES
# ═══════════════════════════════════════════════════════════════════
async def phase_directories(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"tested": 0, "found": 0, "hits": []}
    base = target["base_url"].rstrip("/")

    # baseline for SPA catch-all
    bl = await client.get(base + "/__atomic_nonexistent__")
    baseline_hash = resp_hash(bl) if bl else ""
    baseline_len = resp_len(bl) if bl else 0

    async def _probe(p: str):
        url = base + "/" + p.lstrip("/")
        r = await client.get(url)
        if r is None:
            return None
        if not is_interesting_status(r.status_code):
            return None
        if looks_like_spa_catchall(r, baseline_hash, baseline_len):
            return None
        return {
            "path": p, "url": url, "status": r.status_code,
            "len": resp_len(r), "content_type": r.headers.get("content-type", ""),
            "snippet": body_snippet(r, 120), "hash": resp_hash(r),
        }

    results = await gather_limited([_probe(p) for p in COMMON_DIRS], limit=40)
    hits = [r for r in results if r]
    hits = dedupe(hits, key=lambda x: x["url"])
    data["tested"] = len(COMMON_DIRS)
    data["found"] = len(hits)
    data["hits"] = sorted(hits, key=lambda x: (x["status"], x["path"]))

    for h in data["hits"]:
        sev = "info"
        if h["status"] == 200:
            if any(k in h["path"].lower() for k in
                   (".env", ".git", "config", "backup", "admin", "api")):
                sev = "medium"
        findings.append(make_finding(
            "directory", f"{h['status']} {h['path']}", sev,
            url=h["url"],
            evidence=f"status={h['status']} len={h['len']} type={h['content_type']}\n{h['snippet']}",
            extra={"path": h["path"], "status": h["status"]},
        ))
    return findings, data


async def phase_hidden_files(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"tested": 0, "found": 0, "hits": []}
    base = target["base_url"].rstrip("/")

    bl = await client.get(base + "/__atomic_nonexistent_zzz__")
    baseline_hash = resp_hash(bl) if bl else ""
    baseline_len = resp_len(bl) if bl else 0

    # cap scan to avoid going forever on slow targets
    scan_list = HIDDEN_FILES[:20000]

    async def _probe(p: str):
        url = base + "/" + p.lstrip("/")
        r = await client.get(url, timeout=6.0)
        if r is None:
            return None
        code = r.status_code
        if code not in (200, 301, 302, 401, 403, 405):
            return None
        if code == 200 and baseline_hash and resp_hash(r) == baseline_hash and abs(resp_len(r) - baseline_len) < 40:
            return None
        body = resp_text(r, 4000)
        return {
            "path": p, "url": url, "status": code,
            "len": resp_len(r), "content_type": r.headers.get("content-type", ""),
            "snippet": body_snippet(r, 150),
        }

    results = await gather_limited([_probe(p) for p in scan_list], limit=80)
    hits = [r for r in results if r]
    hits = dedupe(hits, key=lambda x: x["url"])
    data["tested"] = len(scan_list)
    data["found"] = len(hits)
    data["hits"] = hits

    for h in hits:
        sev = "info"
        lpath = h["path"].lower()
        if h["status"] == 200:
            if any(k in lpath for k in (".env", ".git", "id_rsa", "id_ed25519",
                                         "config", ".bak", ".old", ".zip", ".sql",
                                         "wp-config", "credentials", "secrets",
                                         ".htpasswd", "backup", "dump")):
                sev = "high"
            elif any(k in lpath for k in ("admin", "api", "swagger", "debug",
                                          "phpinfo", ".well-known", "server-status",
                                          "actuator")):
                sev = "medium"
        if sev != "info":
            findings.append(make_finding(
                "hidden_file", f"{h['status']} {h['path']}", sev,
                url=h["url"],
                evidence=f"status={h['status']} len={h['len']}\n{h['snippet']}",
                extra={"path": h["path"], "status": h["status"]},
            ))
    return findings, data


async def phase_backups(client: HttpClient, target: dict, dir_hits: list[dict]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"tested": 0, "found": 0, "hits": []}
    base = target["base_url"].rstrip("/")

    candidates = set()
    for h in dir_hits:
        path = h["path"].split("?")[0].rstrip("/")
        if not path:
            continue
        for suf in BACKUP_SUFFIXES:
            candidates.add(path + suf)
    for stem in INTERESTING_DIR_WORDS:
        for suf in (".bak", ".old", ".zip", ".tar.gz", ".sql", ".sql.gz", ".env"):
            candidates.add(stem + suf)

    candidates = list(candidates)[:400]

    async def _probe(p: str):
        url = base + "/" + p.lstrip("/")
        r = await client.get(url, timeout=6.0)
        if r is None or r.status_code != 200:
            return None
        ln = resp_len(r)
        if ln < 32:
            return None
        return {"path": p, "url": url, "len": ln,
                "content_type": r.headers.get("content-type", ""),
                "snippet": body_snippet(r, 150)}

    results = await gather_limited([_probe(c) for c in candidates], limit=40)
    hits = [r for r in results if r]
    data["tested"] = len(candidates)
    data["found"] = len(hits)
    data["hits"] = hits
    for h in hits:
        findings.append(make_finding(
            "backup_file", f"Backup file exposed: {h['path']}", "high",
            url=h["url"],
            evidence=f"len={h['len']} type={h['content_type']}\n{h['snippet']}",
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 9 — ENDPOINTS
# ═══════════════════════════════════════════════════════════════════
async def phase_endpoints(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"endpoints": [], "js_files": [], "robots": [], "sitemap_urls": [],
                  "js_artifacts": [], "api_paths_found": []}
    base = target["base_url"].rstrip("/")
    root = target["root_domain"]

    endpoints = set()

    # 1. main page
    r = await client.get(base)
    body = resp_text(r) if r else ""
    if body:
        for href in parse_links(body, base):
            if root in urlparse(href).netloc or href.startswith(base):
                endpoints.add(href)
        data["js_files"] = parse_scripts(body, base)

    # 2. robots.txt
    r = await client.get(base + "/robots.txt")
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if line.lower().startswith(("allow:", "disallow:")):
                data["robots"].append(line.strip())

    # 3. sitemaps
    for sm in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        r = await client.get(base + sm)
        if r and r.status_code == 200:
            for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", r.text):
                data["sitemap_urls"].append(m.group(1))
                endpoints.add(m.group(1))
            break

    # 4. JS artifacts (fetch each JS file)
    async def _parse_js(url: str):
        jr = await client.get(url, timeout=10.0)
        if jr is None or jr.status_code != 200:
            return None
        return extract_js_artifacts(resp_text(jr), url)

    js_results = await gather_limited([_parse_js(u) for u in data["js_files"][:30]], limit=10)
    for arts in js_results:
        if arts:
            data["js_artifacts"].append(arts)
            for ep in arts.get("endpoints", []):
                if ep.startswith("/"):
                    endpoints.add(base + ep)
                elif ep.startswith("http"):
                    endpoints.add(ep)

    # 5. common API paths
    async def _probe_api(p: str):
        url = base + p
        ar = await client.get(url, timeout=6.0)
        if ar is None:
            return None
        if ar.status_code in (200, 401, 403):
            ct = ar.headers.get("content-type", "")
            if "json" in ct or "graphql" in ct or p.endswith(".json"):
                return {"path": p, "status": ar.status_code, "url": url,
                        "content_type": ct, "snippet": body_snippet(ar, 120)}
        return None

    api_results = await gather_limited([_probe_api(p) for p in API_PATHS], limit=20)
    for hit in api_results:
        if hit:
            data["api_paths_found"].append(hit)
            endpoints.add(hit["url"])
            findings.append(make_finding(
                "api", f"API endpoint reachable: {hit['path']}", "low",
                url=hit["url"],
                evidence=f"{hit['status']} {hit['content_type']}\n{hit['snippet']}",
            ))

    data["endpoints"] = sorted(endpoints)
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 10 — JS ANALYSIS (clicks / fetch / handler interception)
# ═══════════════════════════════════════════════════════════════════
async def phase_js_analysis(client: HttpClient, target: dict, js_files: list[str],
                            endpoints: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {
        "sources": [], "fetch_calls": [], "websockets": [],
        "storage_keys": [], "onclick_handlers": [], "data_attrs": [],
        "sourcemaps": [], "secrets_in_js": [],
    }
    # secrets scanning applied to JS + inline
    import re as _re
    SECRET_REGEX = {k: _re.compile(v) for k, v in SECRET_PATTERNS.items()}

    async def _scan_js(url: str):
        jr = await client.get(url, timeout=10.0)
        if jr is None or jr.status_code != 200:
            return None
        blob = resp_text(jr)
        arts = extract_js_artifacts(blob, url)
        # secrets
        secrets = []
        for name, rx in SECRET_REGEX.items():
            for m in rx.finditer(blob):
                secrets.append({"type": name, "source": url,
                                "match": m.group(0)[:120],
                                "context": blob[max(0, m.start() - 40):m.start() + len(m.group(0)) + 40][:200]})
        return arts, secrets

    tasks = [u for u in js_files if u.endswith(".js") or ".js?" in u][:30]
    results = await gather_limited([_scan_js(u) for u in tasks], limit=10)

    for r in results:
        if not r:
            continue
        arts, secrets = r
        data["sources"].append(arts["source"])
        data["fetch_calls"].extend(arts.get("endpoints", []))
        data["websockets"].extend(arts.get("websockets", []))
        data["storage_keys"].extend(arts.get("storage_keys", []))
        data["onclick_handlers"].extend(arts.get("onclick_handlers", []))
        data["data_attrs"].extend(arts.get("data_attrs", []))
        data["sourcemaps"].extend(arts.get("sourcemaps", []))
        data["secrets_in_js"].extend(secrets)

    # dedupe
    for k in ("fetch_calls", "websockets", "storage_keys", "onclick_handlers",
              "data_attrs", "sourcemaps", "sources"):
        data[k] = sorted(set(data[k]))

    # emit findings
    if data["secrets_in_js"]:
        for s in data["secrets_in_js"][:20]:
            findings.append(make_finding(
                "secrets", f"Hardcoded {s['type']} in JS", "high",
                url=s["source"],
                evidence=f"match: {s['match']}\ncontext: {s['context']}",
                extra={"secret_type": s["type"]},
                remediation="Rotate secret; move to server-side env vars.",
            ))

    # sourcemap = source leak
    for sm in data["sourcemaps"]:
        sm_url = urljoin(target["base_url"], sm)
        r = await client.get(sm_url)
        if r and r.status_code == 200:
            findings.append(make_finding(
                "secrets", f"Source map exposed: {sm}", "low",
                url=sm_url,
                evidence="Application source is retrievable from production.",
                remediation="Disable sourcemaps in production build.",
            ))

    # onclick handlers referencing endpoints
    admin_hits = [e for e in data["fetch_calls"] if any(
        k in e.lower() for k in ("/admin", "/internal", "/private", "/manage", "/debug"))]
    for h in admin_hits[:10]:
        findings.append(make_finding(
            "js", f"Hidden admin endpoint in JS: {h}", "medium",
            url=target["base_url"],
            evidence=f"Referenced but not linked in HTML: {h}",
        ))

    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 11 — ADMIN PROBE
# ═══════════════════════════════════════════════════════════════════
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/admin1", "/admin2", "/admin3", "/adminpanel",
    "/administrator/login", "/admin/login.php", "/admin/login.jsp",
    "/admin/login.aspx", "/admin/login.html",
    "/dashboard", "/dashboard/login", "/panel", "/control",
    "/manager", "/manager/html", "/management", "/manage",
    "/console", "/console/login", "/web-console",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/user/login", "/user/admin", "/users/sign_in",
    "/cpanel", "/webmail", "/whm", "/plesk",
    "/backend", "/backend/login", "/cp", "/controlpanel",
    "/siteadmin", "/site/admin", "/sysadmin",
    "/staff", "/internal", "/private", "/secure",
    "/gateway", "/portal", "/intranet", "/extranet",
]

async def phase_admin_probe(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"tested": len(ADMIN_PATHS), "hits": []}
    base = target["base_url"].rstrip("/")

    async def _probe(p: str):
        url = base + p
        r = await client.get(url, timeout=8.0, follow_redirects=False)
        if r is None:
            return None
        if r.status_code not in (200, 401, 403):
            return None
        body = resp_text(r, 8000)
        has_pass = bool(re.search(r'<input[^>]+type=["\']password', body, re.I))
        is_login_word = any(w in body.lower() for w in ("login", "sign in", "password", "username"))
        if not (has_pass or is_login_word):
            return None
        return {"path": p, "url": url, "status": r.status_code,
                "has_pass_field": has_pass,
                "snippet": body_snippet(r, 150),
                "title": parse_title(body)}

    results = await gather_limited([_probe(p) for p in ADMIN_PATHS], limit=20)
    hits = [r for r in results if r]
    data["hits"] = hits

    for h in hits:
        sev = "medium" if h["status"] == 200 and h["has_pass_field"] else "low"
        findings.append(make_finding(
            "admin_panel", f"Admin/login panel: {h['path']}", sev,
            url=h["url"],
            evidence=f"status={h['status']} title={h['title']!r} password_field={h['has_pass_field']}\n{h['snippet']}",
            extra={"has_pass_field": h["has_pass_field"]},
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 12 — HIDDEN DATABASE INTERFACES
# ═══════════════════════════════════════════════════════════════════
async def phase_hidden_databases(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"tested": 0, "hits": []}
    base = target["base_url"].rstrip("/")
    host = target["host"]

    async def _probe_path(path: str, kind: str):
        url = base + path
        r = await client.get(url, timeout=8.0)
        if r is None:
            return None
        body = resp_text(r)
        markers = DATABASE_SUCCESS_MARKERS.get(kind, [])
        matched_marker = None
        for m in markers:
            if m.lower() in body.lower():
                matched_marker = m
                break
        if not matched_marker:
            # also detect by content-type / JSON structure
            ct = r.headers.get("content-type", "")
            if "json" in ct and r.status_code == 200:
                matched_marker = f"json:{body[:80]}"
            else:
                return None
        return {"kind": kind, "path": path, "url": url,
                "status": r.status_code, "marker": matched_marker,
                "snippet": body_snippet(r, 150)}

    tasks = []
    for kind, paths in DATABASE_UI_PATHS.items():
        for p in paths:
            tasks.append(_probe_path(p, kind))
    data["tested"] = len(tasks)
    results = await gather_limited(tasks, limit=30)
    hits = [r for r in results if r]
    data["hits"] = hits

    # also probe well-known DB ports via HTTP
    db_port_paths = {
        "elasticsearch": 9200, "couchdb": 5984, "redis-commander": 8081,
        "mongo-express": 8081, "neo4j": 7474, "influxdb": 8086,
        "kibana": 5601, "grafana": 3000, "prometheus": 9090,
        "mysql": 3306, "postgres": 5432, "mongodb": 27017, "redis": 6379,
    }
    for kind, port in db_port_paths.items():
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=2.0)
            banner = ""
            try:
                banner = (await asyncio.wait_for(reader.read(200), timeout=1.0)).decode("utf-8", "ignore")
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            data["hits"].append({"kind": kind, "port": port,
                                 "status": "tcp-open", "banner": banner.strip()[:120]})
            findings.append(make_finding(
                "hidden_database",
                f"{kind} service reachable on port {port}", "critical",
                url=f"{host}:{port}",
                evidence=f"TCP connect OK · banner: {banner.strip()[:100] or 'none'}",
                extra={"kind": kind, "port": port},
                remediation=f"Firewall {port} from public; require auth.",
            ))
        except Exception:
            pass

    for h in hits:
        sev = "high"
        if h.get("status") == 401:
            sev = "medium"
        if h.get("status") == 200:
            sev = "critical"
        findings.append(make_finding(
            "hidden_database",
            f"{h['kind']} interface reachable: {h['path']}", sev,
            url=h["url"],
            evidence=f"status={h.get('status')} marker={h.get('marker')}\n{h.get('snippet','')}",
            extra={"kind": h["kind"], "path": h.get("path")},
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 13 — CMS DEEP
# ═══════════════════════════════════════════════════════════════════
async def phase_cms(client: HttpClient, target: dict, tech: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"wordpress": None, "drupal": None, "joomla": None, "magento": None}
    base = target["base_url"].rstrip("/")
    tl = [t.lower() for t in tech]

    if "wordpress" in tl:
        wp = {"version": None, "plugins": [], "themes": [], "users": []}
        # users
        r = await client.get(base + "/wp-json/wp/v2/users")
        if r and r.status_code == 200:
            try:
                for u in r.json():
                    wp["users"].append(u.get("slug") or u.get("name"))
            except Exception:
                pass
        # version
        r = await client.get(base + "/wp-links-opml.php")
        if r and r.status_code == 200:
            m = re.search(r'generator="WordPress/(\d+(?:\.\d+)*)"', r.text)
            if m:
                wp["version"] = m.group(1)
        r = await client.get(base + "/readme.html")
        if r and r.status_code == 200:
            m = re.search(r"Version (\d+(?:\.\d+)*)", r.text)
            if m and not wp["version"]:
                wp["version"] = m.group(1)
        # plugins
        for plugin in ("woocommerce", "contact-form-7", "yoast", "wordpress-seo",
                       "elementor", "wpforms", "akismet", "jetpack", "wordfence",
                       "all-in-one-seo-pack", "really-simple-ssl", "litespeed-cache",
                       "wp-rocket", "wp-file-manager", "duplicator", "updraftplus"):
            for p in (f"/wp-content/plugins/{plugin}/",
                      f"/wp-content/plugins/{plugin}/readme.txt"):
                r = await client.get(base + p, timeout=5.0)
                if r and r.status_code in (200, 401, 403):
                    wp["plugins"].append(plugin)
                    break
        # themes
        for theme in ("twentytwentyfour", "twentytwentythree", "twentytwentytwo",
                      "astra", "generatepress", "oceanwp", "storefront", "divi"):
            r = await client.get(base + f"/wp-content/themes/{theme}/style.css", timeout=5.0)
            if r and r.status_code == 200:
                wp["themes"].append(theme)
        data["wordpress"] = wp

        if wp["version"]:
            findings.append(make_finding(
                "cms", f"WordPress version disclosed: {wp['version']}", "low",
                url=base, evidence=f"Readme or opml exposed version {wp['version']}",
            ))
        if wp["users"]:
            findings.append(make_finding(
                "cms", f"WordPress user enumeration: {len(wp['users'])} users", "medium",
                url=base + "/wp-json/wp/v2/users",
                evidence=", ".join(wp["users"][:10]),
                remediation="Restrict REST API user endpoint.",
            ))
        if wp["plugins"]:
            findings.append(make_finding(
                "cms", f"WordPress plugins detected: {', '.join(wp['plugins'][:8])}", "info",
                url=base, evidence=f"Plugins: {', '.join(wp['plugins'])}",
            ))

    if "drupal" in tl:
        dr = {"version": None}
        r = await client.get(base + "/CHANGELOG.txt")
        if r and r.status_code == 200:
            m = re.search(r"Drupal (\d+(?:\.\d+)*)", r.text)
            if m:
                dr["version"] = m.group(1)
        data["drupal"] = dr
        if dr["version"]:
            findings.append(make_finding(
                "cms", f"Drupal version disclosed: {dr['version']}", "low",
                url=base, evidence=f"CHANGELOG.txt exposed version {dr['version']}",
            ))

    if "joomla" in tl:
        jo = {"version": None}
        r = await client.get(base + "/administrator/manifests/files/joomla.xml")
        if r and r.status_code == 200:
            m = re.search(r"<version>([^<]+)</version>", r.text)
            if m:
                jo["version"] = m.group(1)
        data["joomla"] = jo
        if jo["version"]:
            findings.append(make_finding(
                "cms", f"Joomla version disclosed: {jo['version']}", "low",
                url=base, evidence=f"manifest file exposed version {jo['version']}",
            ))

    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 14 — SECRETS
# ═══════════════════════════════════════════════════════════════════
async def phase_secrets(client: HttpClient, target: dict, js_files: list[str],
                        body_html: str) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"count": 0, "findings": []}
    SECRET_REGEX = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}

    blobs = [("html", body_html)]
    for u in js_files[:25]:
        r = await client.get(u)
        if r and r.status_code == 200:
            blobs.append((u, resp_text(r)))

    for source, blob in blobs:
        if not blob:
            continue
        for name, rx in SECRET_REGEX.items():
            for m in rx.finditer(blob):
                val = m.group(0)[:120]
                ctx = blob[max(0, m.start() - 40):m.start() + len(val) + 40][:200]
                data["findings"].append({
                    "type": name, "source": source, "match": val, "context": ctx,
                })
                findings.append(make_finding(
                    "secrets", f"Secret detected: {name}", "high",
                    url=source,
                    evidence=f"match: {val}\ncontext: {ctx}",
                    extra={"type": name},
                    remediation="Rotate secret; move out of client-side assets.",
                ))
    data["count"] = len(data["findings"])
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 15 — PARAM DISCOVERY
# ═══════════════════════════════════════════════════════════════════
async def phase_params(client: HttpClient, target: dict, endpoints: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"endpoints_with_params": []}
    base = target["base_url"]
    candidates = [u for u in endpoints if u.startswith(base) and "?" not in u][:12]

    for url in candidates:
        baseline = await client.get(url)
        if baseline is None:
            continue
        base_len = resp_len(baseline)
        base_hash = resp_hash(baseline)
        found = []
        # probe each param name with a marker value
        for pname in COMMON_PARAM_NAMES[:80]:
            marker = f"atomic_{pname}"
            test = url + ("&" if "?" in url else "?") + f"{pname}={marker}"
            r = await client.get(test)
            if r is None:
                continue
            if r.status_code != baseline.status_code or \
                    resp_hash(r) != base_hash or abs(resp_len(r) - base_len) > 40:
                found.append({"param": pname, "status": r.status_code,
                              "len_diff": resp_len(r) - base_len})
        if found:
            data["endpoints_with_params"].append({"url": url, "params": found[:30]})
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 16 — GRAPHQL
# ═══════════════════════════════════════════════════════════════════
async def phase_graphql(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"findings": []}
    base = target["base_url"].rstrip("/")

    introspection = {"query": "{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind}}}"}
    paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query", "/api/query"]
    for p in paths:
        url = base + p
        r = await client.post(url, json=introspection, timeout=10.0)
        if r is None or r.status_code != 200:
            continue
        try:
            j = r.json()
        except Exception:
            continue
        schema = j.get("data", {}).get("__schema")
        if not schema:
            continue
        types = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
        rec = {
            "url": url,
            "query_type": (schema.get("queryType") or {}).get("name"),
            "mutation_type": (schema.get("mutationType") or {}).get("name"),
            "types": types[:60],
        }
        data["findings"].append(rec)
        findings.append(make_finding(
            "graphql", f"GraphQL introspection enabled at {p}", "medium",
            url=url,
            evidence=f"queryType={rec['query_type']} mutationType={rec['mutation_type']} "
                     f"types={len(types)}",
            extra={"types": types[:30]},
            remediation="Disable introspection in production.",
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 17 — OPEN REDIRECT HINT
# ═══════════════════════════════════════════════════════════════════
async def phase_open_redirect_hint(client: HttpClient, target: dict,
                                   endpoints: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"findings": []}
    base = target["base_url"]

    # only informational detection — full testing in breaker.py
    param_urls = [u for u in endpoints if url_has_query(u)][:20]
    from .armory import REDIRECT_PARAM_HINTS
    for url in param_urls:
        params = url_params(url)
        for rp in params:
            if rp.lower() in REDIRECT_PARAM_HINTS:
                data["findings"].append({"url": url, "param": rp})
                findings.append(make_finding(
                    "open_redirect_hint",
                    f"Potential open redirect param: {rp}", "info",
                    url=url,
                    evidence=f"Parameter {rp} typically used for redirects; verify.",
                ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 18 — TAKEOVER
# ═══════════════════════════════════════════════════════════════════
async def phase_takeover(client: HttpClient, target: dict,
                        subdomains: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"vulnerable": []}

    async def _probe(sub: str):
        # check DNS CNAME first
        resolver = DNSResolver()
        cname_vals = await resolver.async_query(sub, "CNAME")
        target_hosts = cname_vals or [sub]

        for host in target_hosts:
            for provider, markers in TAKEOVER_FINGERPRINTS.items():
                if provider in host.lower() or provider in sub.lower():
                    for scheme in ("https", "http"):
                        r = await client.get(f"{scheme}://{sub}", timeout=8.0)
                        if r is None:
                            continue
                        body = resp_text(r).lower()
                        for m in markers:
                            if m.lower() in body:
                                return {"subdomain": sub, "provider": provider,
                                        "marker": m, "status": r.status_code}
        return None

    results = await gather_limited([_probe(s) for s in subdomains[:200]], limit=20)
    for r in results:
        if r:
            data["vulnerable"].append(r)
            findings.append(make_finding(
                "takeover", f"Subdomain takeover candidate: {r['subdomain']}", "high",
                url=f"https://{r['subdomain']}",
                evidence=f"CNAME points to {r['provider']} · marker: {r['marker']!r}",
                extra={"provider": r["provider"]},
                remediation="Remove dangling CNAME or claim the cloud resource.",
            ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 19 — BUCKETS
# ═══════════════════════════════════════════════════════════════════
async def phase_buckets(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"hits": []}
    root = target["root_domain"]
    stem = root.split(".")[0]

    candidates = [stem, root.replace(".", "-"), root.replace(".", ""),
                  f"{stem}-assets", f"{stem}-static", f"{stem}-backup",
                  f"{stem}-dev", f"{stem}-media", f"{stem}-cdn", f"{stem}-files",
                  f"{stem}-prod", f"{stem}-storage", f"{stem}-data", f"{stem}-uploads"]

    providers = {
        "s3": "https://{name}.s3.amazonaws.com/",
        "gcs": "https://storage.googleapis.com/{name}/",
        "azure": "https://{name}.blob.core.windows.net/",
    }

    for name in candidates:
        for prov, tpl in providers.items():
            url = tpl.format(name=name)
            r = await client.get(url, timeout=6.0)
            if r is None:
                continue
            body = resp_text(r, 800)
            if prov == "s3":
                if "NoSuchBucket" in body:
                    continue
                if "<ListBucketResult" in body and r.status_code == 200:
                    data["hits"].append({"provider": "s3", "name": name, "url": url,
                                         "status": 200, "state": "listable"})
                    findings.append(make_finding(
                        "exposed_bucket", f"S3 bucket listable: {name}", "high",
                        url=url, evidence="ListBucketResult returned — bucket contents enumerable.",
                        remediation="Block anonymous list; use bucket policy.",
                    ))
                elif r.status_code == 403:
                    data["hits"].append({"provider": "s3", "name": name, "url": url,
                                         "status": 403, "state": "exists"})
            elif prov == "gcs":
                if "NoSuchBucket" in body:
                    continue
                if r.status_code == 200 and "<ListBucketResult" in body:
                    findings.append(make_finding(
                        "exposed_bucket", f"GCS bucket listable: {name}", "high",
                        url=url, evidence="ListBucketResult returned.",
                    ))
            elif prov == "azure":
                if "ResourceNotFound" in body or "InvalidUri" in body:
                    continue
                if r.status_code in (200, 400):
                    data["hits"].append({"provider": "azure", "name": name,
                                         "url": url, "status": r.status_code,
                                         "state": "exists"})
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 20 — EMAILS
# ═══════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

async def phase_emails(client: HttpClient, target: dict,
                       urls: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"count": 0, "emails": []}
    root = target["root_domain"]
    pages = [target["base_url"]] + [u for u in urls if u.startswith("http")][:10]
    seen = set()

    async def _scan(url):
        r = await client.get(url)
        if r is None or r.status_code != 200:
            return set()
        out = set()
        for m in EMAIL_RE.finditer(resp_text(r)):
            e = m.group(0).lower()
            if e.endswith(f"@{root}") or root in e:
                out.add(e)
        return out

    results = await gather_limited([_scan(u) for u in pages], limit=10)
    for s in results:
        if s:
            seen |= s
    data["emails"] = sorted(seen)
    data["count"] = len(seen)
    if seen:
        findings.append(make_finding(
            "email", f"{len(seen)} email address(es) harvested", "info",
            url=root, evidence=", ".join(sorted(seen)[:20]),
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# PHASE 21 — LOGIN FINDER
# ═══════════════════════════════════════════════════════════════════
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/auth/login",
    "/admin/login", "/wp-login.php", "/user/login",
    "/account/login", "/portal/login", "/cpanel", "/dashboard/login",
    "/session/new", "/users/sign_in", "/administrator/index.php",
    "/login.php", "/login.jsp", "/login.aspx", "/login.html",
    "/console/login", "/manager/html", "/admin/index",
]

async def phase_logins(client: HttpClient, target: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {"tested": len(LOGIN_PATHS), "found": 0, "logins": []}
    base = target["base_url"].rstrip("/")

    async def _probe(p: str):
        url = base + p
        r = await client.get(url)
        if r is None or r.status_code >= 500:
            return None
        body = resp_text(r)
        if not re.search(r'<input[^>]+type=["\']password', body, re.I):
            return None
        forms = parse_forms(body)
        pass_forms = [f for f in forms if any(i["type"] == "password" for i in f["inputs"])]
        if not pass_forms:
            return None
        return {
            "url": url, "status": r.status_code, "title": parse_title(body),
            "forms": pass_forms,
        }

    results = await gather_limited([_probe(p) for p in LOGIN_PATHS], limit=15)
    hits = [r for r in results if r]
    data["logins"] = hits
    data["found"] = len(hits)
    for h in hits:
        findings.append(make_finding(
            "login", f"Login form: {urlparse(h['url']).path}", "info",
            url=h["url"],
            evidence=f"forms={len(h['forms'])} title={h['title']!r}",
            extra={"forms": h["forms"]},
        ))
    return findings, data


# ═══════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════
async def run(client: HttpClient, target: dict, progress=None) -> tuple[list[Finding], dict]:
    """Run all phases. Returns (findings, data)."""
    findings: list[Finding] = []
    data: dict = {}

    def step(name):
        if progress:
            progress(name)

    # DNS + WHOIS + TLS
    step("dns")
    f, data["dns"] = await phase_dns(target); findings += f
    step("whois")
    f, data["whois"] = await phase_whois(target); findings += f
    step("tls")
    f, data["tls"] = await phase_tls(target); findings += f

    # fingerprint
    step("fingerprint")
    f, data["fingerprint"] = await phase_fingerprint(client, target); findings += f

    # WAF
    step("waf")
    f, data["waf"] = await phase_waf(client, target); findings += f

    # security headers / cors / host header / methods
    step("headers")
    f, data["headers"] = await phase_headers(client, target); findings += f
    step("cors")
    f, data["cors"] = await phase_cors(client, target); findings += f
    step("host_header")
    f, data["host_header"] = await phase_host_header(client, target); findings += f
    step("methods")
    f, data["methods"] = await phase_methods(client, target); findings += f

    # surface
    step("subdomains")
    f, data["subdomains"] = await phase_subdomains(client, target, data["tls"]); findings += f
    step("ports")
    f, data["ports"] = await phase_ports(target); findings += f
    step("wayback")
    f, data["wayback"] = await phase_wayback(client, target); findings += f

    # discovery
    step("directories")
    f, data["directories"] = await phase_directories(client, target); findings += f
    step("hidden_files")
    f, data["hidden_files"] = await phase_hidden_files(client, target); findings += f
    step("backups")
    f, data["backups"] = await phase_backups(client, target, data["directories"]["hits"]); findings += f

    # app
    step("endpoints")
    f, data["endpoints"] = await phase_endpoints(client, target); findings += f
    step("js_analysis")
    f, data["js_analysis"] = await phase_js_analysis(
        client, target, data["endpoints"]["js_files"], data["endpoints"]["endpoints"]
    ); findings += f
    step("admin_probe")
    f, data["admin_probe"] = await phase_admin_probe(client, target); findings += f
    step("hidden_databases")
    f, data["hidden_databases"] = await phase_hidden_databases(client, target); findings += f
    step("cms")
    f, data["cms"] = await phase_cms(client, target, data["fingerprint"].get("tech", [])); findings += f
    step("secrets")
    body_html = ""
    if client:
        r = await client.get(target["base_url"])
        if r:
            body_html = resp_text(r)
    f, data["secrets"] = await phase_secrets(client, target, data["endpoints"]["js_files"], body_html); findings += f
    step("params")
    f, data["params"] = await phase_params(client, target, data["endpoints"]["endpoints"]); findings += f
    step("graphql")
    f, data["graphql"] = await phase_graphql(client, target); findings += f

    # data
    step("buckets")
    f, data["buckets"] = await phase_buckets(client, target); findings += f
    step("emails")
    f, data["emails"] = await phase_emails(client, target, data["endpoints"]["sitemap_urls"]); findings += f

    # hints
    step("takeover")
    f, data["takeover"] = await phase_takeover(client, target, data["subdomains"]["subdomains"]); findings += f
    step("open_redirect_hint")
    f, data["open_redirect_hint"] = await phase_open_redirect_hint(client, target, data["endpoints"]["endpoints"]); findings += f

    # logins last (breaker.py picks up from here)
    step("logins")
    f, data["logins"] = await phase_logins(client, target); findings += f

    return dedupe_findings(findings), data
