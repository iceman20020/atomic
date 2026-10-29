"""
breaker.py — active exploitation and confirmation testing.

Every test produces a Finding with proof attached, or nothing. Runs only
after operator confirmation. Never assumes.
"""
from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from typing import Optional
from urllib.parse import urlparse, urljoin, urlunparse, urlencode, parse_qs

from .spine import (
    HttpClient, Finding, make_finding, resp_len, resp_text, resp_hash,
    body_snippet, header_dict, url_with_param, url_params, url_has_query,
    now,
)
from .armory import (
    SQLI_ERROR_PAYLOADS, SQLI_BOOLEAN_PAYLOADS, SQLI_TIME_PAYLOADS,
    SQLI_UNION_PAYLOADS, SQLI_ERROR_SIGNATURES,
    XSS_PAYLOADS, LFI_PAYLOADS, LFI_SUCCESS_MARKERS, LFI_PARAM_HINTS,
    SSRF_PAYLOADS, SSRF_PARAM_HINTS,
    SSTI_PAYLOADS, SSTI_PARAM_HINTS,
    XXE_PAYLOADS,
    CMD_PAYLOADS, CMD_PARAM_HINTS,
    NOSQL_PAYLOADS, NOSQL_SUCCESS_MARKERS,
    CRLF_PAYLOADS,
    REDIRECT_PAYLOADS, REDIRECT_PARAM_HINTS,
    JWT_WEAK_SECRETS, JWT_ALGORITHMS,
    PROBE_CREDS,
)


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION — error / boolean / time / union
# ═══════════════════════════════════════════════════════════════════
_SQLI_RE = re.compile("|".join(f"(?:{s})" for s in SQLI_ERROR_SIGNATURES), re.I)


async def test_sqli_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    """Test one parameterized URL. Returns findings."""
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out: list[Finding] = []

    for param in params:
        # baseline
        baseline = await client.get(url_with_param(url, param, "atomic_baseline"))
        baseline_len = resp_len(baseline)
        baseline_hash = resp_hash(baseline)

        # error-based
        for payload in SQLI_ERROR_PAYLOADS:
            r = await client.get(url_with_param(url, param, payload))
            if r is None:
                continue
            body = resp_text(r)
            m = _SQLI_RE.search(body)
            if m:
                out.append(make_finding(
                    "sqli", f"Error-based SQLi in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload!r}\nerror={m.group(0)[:200]}",
                    extra={"param": param, "technique": "error-based", "payload": payload},
                    remediation="Use parameterized queries.",
                ))
                return out  # stop on confirmed error-based

        # boolean-based
        true_hits, false_hits = 0, 0
        for payload, is_true in SQLI_BOOLEAN_PAYLOADS[:6]:
            r = await client.get(url_with_param(url, param, payload))
            if r is None:
                continue
            same_len = abs(resp_len(r) - baseline_len) < 40
            same_hash = resp_hash(r) == baseline_hash
            if is_true and (same_hash or same_len):
                true_hits += 1
            elif not is_true and not (same_hash or same_len):
                false_hits += 1
        if true_hits >= 2 and false_hits >= 2:
            out.append(make_finding(
                "sqli", f"Boolean-based SQLi in {param}", "critical",
                url=url_with_param(url, param, SQLI_BOOLEAN_PAYLOADS[0][0]),
                evidence=f"{true_hits} true-condition responses matched baseline, "
                         f"{false_hits} false-condition responses diverged.",
                extra={"param": param, "technique": "boolean-based"},
            ))
            return out

        # time-based
        for payload, delay in SQLI_TIME_PAYLOADS:
            t0 = now()
            r = await client.get(url_with_param(url, param, payload), timeout=delay + 8)
            dt = now() - t0
            if r is not None and dt >= delay - 0.6:
                out.append(make_finding(
                    "sqli", f"Time-based blind SQLi in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload!r} delayed {dt:.2f}s (expected ≥{delay}s)",
                    extra={"param": param, "technique": "time-based", "payload": payload},
                ))
                return out

    return out


# ═══════════════════════════════════════════════════════════════════
# XSS — reflected
# ═══════════════════════════════════════════════════════════════════
async def test_xss_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out: list[Finding] = []

    for param in params:
        for payload in XSS_PAYLOADS[:15]:
            r = await client.get(url_with_param(url, param, payload))
            if r is None:
                continue
            body = resp_text(r)
            if payload in body:
                # extract a context snippet
                idx = body.find(payload)
                ctx = body[max(0, idx - 60):idx + len(payload) + 60]
                out.append(make_finding(
                    "xss", f"Reflected XSS in {param}", "high",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload}\ncontext=...{ctx[:220]}...",
                    extra={"param": param, "payload": payload},
                    remediation="HTML-encode output; add CSP.",
                ))
                return out
    return out


# ═══════════════════════════════════════════════════════════════════
# LFI
# ═══════════════════════════════════════════════════════════════════
async def test_lfi_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out: list[Finding] = []

    for param in params:
        # parameter name filtering: try even if not in hints
        for payload in LFI_PAYLOADS:
            r = await client.get(url_with_param(url, param, payload))
            if r is None:
                continue
            body = resp_text(r)
            for marker in LFI_SUCCESS_MARKERS:
                if marker in body:
                    idx = body.find(marker)
                    out.append(make_finding(
                        "lfi", f"Local File Inclusion in {param}", "critical",
                        url=url_with_param(url, param, payload),
                        evidence=f"payload={payload}\nproof=...{body[max(0,idx-40):idx+120]}...",
                        extra={"param": param, "payload": payload},
                        remediation="Validate/whitelist file path parameter.",
                    ))
                    return out
    return out


# ═══════════════════════════════════════════════════════════════════
# RFI — lightweight, only if LFI worked
# ═══════════════════════════════════════════════════════════════════
async def test_rfi_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    """Only mark RFI if a URL inclusion caused the target to fetch from us.
    Without an OOB listener we detect via included-response differences."""
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out = []
    # We test that target includes a known-content URL. If it returns the
    # contents of data: URI, RFI is on.
    test_payload = "data://text/plain,atomic_rfi_marker_9173"
    for param in params:
        r = await client.get(url_with_param(url, param, test_payload))
        if r is None:
            continue
        if "atomic_rfi_marker_9173" in resp_text(r):
            out.append(make_finding(
                "rfi", f"Remote File Inclusion in {param}", "critical",
                url=url_with_param(url, param, test_payload),
                evidence="Target included data: URI contents.",
                extra={"param": param},
            ))
            return out
    return out


# ═══════════════════════════════════════════════════════════════════
# SSRF
# ═══════════════════════════════════════════════════════════════════
async def test_ssrf_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out = []
    for param in params:
        if not any(h in param.lower() for h in SSRF_PARAM_HINTS):
            continue
        for payload in SSRF_PAYLOADS:
            r = await client.get(url_with_param(url, param, payload), timeout=10)
            if r is None:
                continue
            body = resp_text(r)
            low = body.lower()
            if "169.254.169.254" in body or "ami-id" in low or "instance-id" in low:
                out.append(make_finding(
                    "ssrf", f"SSRF to cloud metadata in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload}\nmetadata marker present.",
                    extra={"param": param, "payload": payload},
                ))
                return out
            if "root:x:0" in body:
                out.append(make_finding(
                    "ssrf", f"SSRF to local file in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload}\nfile contents leaked.",
                    extra={"param": param, "payload": payload},
                ))
                return out
            if "redis_version" in low or "connected_clients" in low:
                out.append(make_finding(
                    "ssrf", f"SSRF to internal service in {param}", "high",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload}\ninternal service fingerprint.",
                ))
                return out
    return out


# ═══════════════════════════════════════════════════════════════════
# SSTI
# ═══════════════════════════════════════════════════════════════════
async def test_ssti_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out = []
    for param in params:
        for payload, expected in SSTI_PAYLOADS:
            r = await client.get(url_with_param(url, param, payload))
            if r is None:
                continue
            body = resp_text(r)
            # expected is the *rendered* value (49, 7777777 etc)
            if expected in body and payload not in body:
                out.append(make_finding(
                    "ssti", f"Server-Side Template Injection in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload!r} rendered as {expected!r}",
                    extra={"param": param, "payload": payload},
                ))
                return out
    return out


# ═══════════════════════════════════════════════════════════════════
# XXE
# ═══════════════════════════════════════════════════════════════════
async def test_xxe_endpoint(client: HttpClient, url: str) -> list[Finding]:
    out = []
    for payload in XXE_PAYLOADS:
        r = await client.post(url, content=payload,
                              headers={"Content-Type": "application/xml"})
        if r is None:
            continue
        body = resp_text(r)
        if "root:x:0" in body or "[extensions]" in body:
            out.append(make_finding(
                "xxe", "XML External Entity injection", "critical",
                url=url,
                evidence=f"payload sent; local file contents returned in response.",
                remediation="Disable external entity processing in XML parser.",
            ))
            return out
        if "xxe-test" in body:
            out.append(make_finding(
                "xxe", "XML entity substitution active", "medium",
                url=url,
                evidence="Internal entity expanded in response.",
            ))
            return out
    return out


# ═══════════════════════════════════════════════════════════════════
# COMMAND INJECTION
# ═══════════════════════════════════════════════════════════════════
async def test_cmd_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    out = []
    for param in params:
        if not any(h in param.lower() for h in CMD_PARAM_HINTS):
            continue
        for payload, expected in CMD_PAYLOADS:
            t0 = now()
            r = await client.get(url_with_param(url, param, payload), timeout=15)
            dt = now() - t0
            if r is None:
                continue
            body = resp_text(r)
            if expected != "delay" and expected in body:
                out.append(make_finding(
                    "command_injection", f"Command injection in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload!r}\nproof={expected!r} in response.",
                    extra={"param": param, "payload": payload},
                    remediation="Never pass user input to shell.",
                ))
                return out
            if expected == "delay" and dt >= 2.5:
                out.append(make_finding(
                    "command_injection", f"Blind command injection in {param}", "critical",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload!r} caused {dt:.2f}s delay.",
                    extra={"param": param, "payload": payload},
                ))
                return out
    return out


# ═══════════════════════════════════════════════════════════════════
# NoSQL
# ═══════════════════════════════════════════════════════════════════
async def test_nosql_login(client: HttpClient, login_form: dict, base_url: str) -> list[Finding]:
    """Send JSON NoSQL payloads to login forms."""
    out = []
    form = login_form["forms"][0]
    action = urljoin(base_url, form.get("action") or base_url)
    method = form["method"].upper()
    user_field = next((i["name"] for i in form["inputs"]
                       if i["type"] in ("text", "email")), None)
    pass_field = next((i["name"] for i in form["inputs"]
                       if i["type"] == "password"), None)
    if not user_field or not pass_field:
        return out

    # baseline
    baseline = await client.post(action, data={user_field: "atomic_user_1",
                                                pass_field: "atomic_pass_1"})
    base_hash = resp_hash(baseline) if baseline else ""

    for payload, _ in NOSQL_PAYLOADS:
        # attempt JSON body
        try:
            data = json.loads(payload)
            r = await client.post(action, json={user_field: data, pass_field: data})
        except Exception:
            # fall back to raw form
            r = await client.post(action, data={user_field: payload, pass_field: payload})
        if r is None:
            continue
        body = resp_text(r)
        for marker in NOSQL_SUCCESS_MARKERS:
            if marker.lower() in body.lower() and resp_hash(r) != base_hash:
                out.append(make_finding(
                    "nosql", "NoSQL injection possible on login", "critical",
                    url=action,
                    evidence=f"payload={payload}\nmarker={marker!r} appeared in response.",
                    extra={"param": user_field},
                ))
                return out
    return out


# ═══════════════════════════════════════════════════════════════════
# CRLF
# ═══════════════════════════════════════════════════════════════════
async def test_crlf_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    for param in params:
        for payload in CRLF_PAYLOADS:
            r = await client.get(url_with_param(url, param, payload), follow_redirects=False)
            if r is None:
                continue
            h = header_dict(r)
            if "atomic=1" in h.get("set-cookie", "").lower() or "x-atomic" in h:
                return [make_finding(
                    "crlf", f"CRLF injection in {param}", "high",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload}\ninjected header observed.",
                    extra={"param": param, "payload": payload},
                )]
    return []


# ═══════════════════════════════════════════════════════════════════
# OPEN REDIRECT
# ═══════════════════════════════════════════════════════════════════
async def test_open_redirect_url(client: HttpClient, url: str, params: list[str] | None = None) -> list[Finding]:
    if not url_has_query(url):
        return []
    params = params or url_params(url)
    for param in params:
        if param.lower() not in REDIRECT_PARAM_HINTS:
            continue
        for payload in REDIRECT_PAYLOADS:
            r = await client.get(url_with_param(url, param, payload), follow_redirects=False)
            if r is None:
                continue
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            loc = r.headers.get("location", "")
            if "atomic.example" in loc or "evil.example" in loc:
                return [make_finding(
                    "open_redirect", f"Open redirect in {param}", "medium",
                    url=url_with_param(url, param, payload),
                    evidence=f"payload={payload!r} → Location: {loc[:200]}",
                    extra={"param": param, "payload": payload},
                    remediation="Whitelist allowed redirect destinations.",
                )]
    return []


# ═══════════════════════════════════════════════════════════════════
# BRUTE FEASIBILITY (probe only, not brute)
# ═══════════════════════════════════════════════════════════════════
async def test_brute_feasibility(client: HttpClient, login: dict, base_url: str) -> Optional[Finding]:
    form = login["forms"][0]
    action = urljoin(base_url, form.get("action") or base_url)
    method = form["method"].upper()
    user_field = next((i["name"] for i in form["inputs"]
                       if i["type"] in ("text", "email") or "user" in i["name"].lower()), None)
    pass_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)
    if not user_field or not pass_field:
        return None

    responses = []
    start = now()
    for user, pw in PROBE_CREDS[:10]:
        data = {user_field: user, pass_field: pw}
        for i in form["inputs"]:
            if i["type"] == "hidden" and i["name"] not in data:
                data[i["name"]] = i["value"]
        r = await (client.post(action, data=data) if method == "POST"
                   else client.get(action, params=data))
        if r is None:
            continue
        responses.append({
            "status": r.status_code,
            "len": resp_len(r),
            "snippet": body_snippet(r, 200).lower(),
        })
        await asyncio.sleep(0.4)

    if not responses:
        return None

    elapsed = now() - start
    avg = elapsed / len(responses)
    statuses = {x["status"] for x in responses}
    captcha = any("captcha" in x["snippet"] or "recaptcha" in x["snippet"] for x in responses)
    rl = 429 in statuses or 503 in statuses
    distinct_lens = {x["len"] for x in responses}

    if captcha:
        return make_finding(
            "brute_feasible", f"Login protected by captcha", "info",
            url=action,
            evidence="Captcha markers in response body; brute likely infeasible.",
            extra={"user_field": user_field, "pass_field": pass_field},
        )
    if rl:
        return make_finding(
            "brute_feasible", f"Login rate-limited", "info",
            url=action,
            evidence=f"HTTP 429/503 observed at {avg:.2f}s/req average.",
            extra={"user_field": user_field, "pass_field": pass_field},
        )
    if len(distinct_lens) <= 2 and avg < 1.0:
        return make_finding(
            "brute_feasible", f"Login brute-force feasible", "medium",
            url=action,
            evidence=f"No throttle; consistent error response at {avg:.2f}s/req.",
            extra={"user_field": user_field, "pass_field": pass_field,
                   "avg_req_s": round(avg, 2)},
            remediation="Add rate-limiting or captcha to login endpoint.",
        )
    return None


# ═══════════════════════════════════════════════════════════════════
# JWT WEAK SECRET
# ═══════════════════════════════════════════════════════════════════
def _jwt_hs256(header: dict, payload: dict, secret: str) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=")
    p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    signing_input = h + b"." + p
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (signing_input + b"." + s).decode()


def test_jwt_weak(token: str) -> list[Finding]:
    out = []
    parts = token.split(".")
    if len(parts) != 3:
        return out
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except Exception:
        return out
    alg = header.get("alg")
    if alg not in JWT_ALGORITHMS:
        return out
    for secret in JWT_WEAK_SECRETS:
        try:
            forged = _jwt_hs256({"alg": alg, "typ": "JWT"}, {"sub": "atomic_test"}, secret)
        except Exception:
            continue
        # verify by comparing signature bytes
        if forged.split(".")[2] == parts[2]:
            out.append(make_finding(
                "jwt", f"JWT signed with weak secret: {secret!r}", "critical",
                url="",
                evidence=f"alg={alg} secret={secret!r} — signature matched.",
                extra={"secret": secret, "alg": alg},
                remediation="Rotate JWT signing secret.",
            ))
            return out
    return out


# ═══════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════
async def run(client: HttpClient, target: dict, data: dict,
              progress=None, selected: set[str] | None = None) -> tuple[list[Finding], dict]:
    """
    Run active tests against findings from specter.

    selected: subset of {'sqli','xss','lfi','rfi','ssrf','ssti','xxe',
                         'cmdi','nosql','crlf','redirect','brute','jwt'}
    """
    findings: list[Finding] = []
    out_data: dict = {}
    base = target["base_url"]

    def step(name):
        if progress:
            progress(name)

    eps = data.get("endpoints", {}).get("endpoints", [])
    param_urls = [u for u in eps if url_has_query(u)]
    # cap for tractability
    param_urls = param_urls[:80]

    def want(cat: str) -> bool:
        return selected is None or cat in selected

    # SQLi
    if want("sqli"):
        step("sqli")
        hits = []
        for u in param_urls:
            h = await test_sqli_url(client, u)
            hits.extend(h)
            if len(hits) >= 5:
                break
        findings.extend(hits)
        out_data["sqli"] = hits

    # XSS
    if want("xss"):
        step("xss")
        hits = []
        for u in param_urls:
            h = await test_xss_url(client, u)
            hits.extend(h)
            if len(hits) >= 5:
                break
        findings.extend(hits)
        out_data["xss"] = hits

    # LFI / RFI
    if want("lfi"):
        step("lfi")
        hits = []
        for u in param_urls:
            h = await test_lfi_url(client, u)
            hits.extend(h)
            if len(hits) >= 3:
                break
        findings.extend(hits)
        out_data["lfi"] = hits
        if hits and want("rfi"):
            step("rfi")
            rfi_hits = []
            for u in param_urls:
                h = await test_rfi_url(client, u)
                rfi_hits.extend(h)
            findings.extend(rfi_hits)
            out_data["rfi"] = rfi_hits

    # SSRF
    if want("ssrf"):
        step("ssrf")
        hits = []
        for u in param_urls:
            h = await test_ssrf_url(client, u)
            hits.extend(h)
            if len(hits) >= 3:
                break
        findings.extend(hits)
        out_data["ssrf"] = hits

    # SSTI
    if want("ssti"):
        step("ssti")
        hits = []
        for u in param_urls:
            h = await test_ssti_url(client, u)
            hits.extend(h)
            if len(hits) >= 3:
                break
        findings.extend(hits)
        out_data["ssti"] = hits

    # XXE — target JSON/XML endpoints
    if want("xxe"):
        step("xxe")
        xml_candidates = [u for u in eps if any(
            k in u.lower() for k in ("/xml", "/soap", "/wsdl", "/rpc"))][:5]
        hits = []
        for u in xml_candidates:
            h = await test_xxe_endpoint(client, u)
            hits.extend(h)
        findings.extend(hits)
        out_data["xxe"] = hits

    # command injection
    if want("cmdi"):
        step("cmdi")
        hits = []
        for u in param_urls:
            h = await test_cmd_url(client, u)
            hits.extend(h)
            if len(hits) >= 3:
                break
        findings.extend(hits)
        out_data["cmdi"] = hits

    # NoSQL — on discovered logins
    if want("nosql"):
        step("nosql")
        hits = []
        for login in data.get("logins", {}).get("logins", [])[:5]:
            h = await test_nosql_login(client, login, base)
            hits.extend(h)
        findings.extend(hits)
        out_data["nosql"] = hits

    # CRLF
    if want("crlf"):
        step("crlf")
        hits = []
        for u in param_urls[:30]:
            h = await test_crlf_url(client, u)
            hits.extend(h)
            if hits:
                break
        findings.extend(hits)
        out_data["crlf"] = hits

    # open redirect
    if want("redirect"):
        step("redirect")
        hits = []
        for u in param_urls[:30]:
            h = await test_open_redirect_url(client, u)
            hits.extend(h)
            if len(hits) >= 3:
                break
        findings.extend(hits)
        out_data["redirect"] = hits

    # brute feasibility
    if want("brute"):
        step("brute")
        hits = []
        for login in data.get("logins", {}).get("logins", [])[:5]:
            h = await test_brute_feasibility(client, login, base)
            if h:
                hits.append(h)
        findings.extend(hits)
        out_data["brute"] = hits

    # JWT weakness — on any JWT found in secrets
    if want("jwt"):
        step("jwt")
        hits = []
        for s in data.get("secrets", {}).get("findings", []):
            if s["type"] == "jwt":
                h = test_jwt_weak(s["match"])
                hits.extend(h)
        findings.extend(hits)
        out_data["jwt"] = hits

    return findings, out_data
