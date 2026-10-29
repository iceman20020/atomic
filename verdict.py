"""
verdict.py — the report.

Renders one self-contained HTML file. Animated green-black cover, executive
brief, exposure summary, key judgments, capability callouts, risk register,
findings register, and category annexes. Exports matching JSON.
"""
from __future__ import annotations
import html
import json
import os
import time
from typing import Any


# ═══════════════════════════════════════════════════════════════════
# ASSETS
# ═══════════════════════════════════════════════════════════════════
BANNER_ART = """  █████╗ ████████╗ ██████╗  ███╗   ███╗ ██╗  ██████╗
 ██╔══██╗╚══██╔══╝██╔═══██╗ ████╗ ████║ ██║ ██╔════╝
 ███████║   ██║   ██║   ██║ ██╔████╔██║ ██║ ██║     
 ██╔══██║   ██║   ██║   ██║ ██║╚██╔╝██║ ██║ ██║     
 ██║  ██║   ██║   ╚██████╔╝ ██║ ╚═╝ ██║ ██║ ╚██████╗
 ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═╝     ╚═╝ ╚═╝  ╚═════╝"""

CSS = r"""
:root{
  --bg:#0a0e0c; --bg-2:#0f1512; --bg-3:#141b17;
  --line:#1e2822; --line-2:#2b3830;
  --green:#4ade80; --green-2:#22c55e; --green-3:#86efac; --green-dim:#166534;
  --text:#d4e0d8; --text-2:#8a9a90; --text-3:#5a6b60;
  --mono:"JetBrains Mono","SF Mono",ui-monospace,Menlo,Consolas,monospace;
  --sans:"Inter","SF Pro Display",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --crit:#f87171; --high:#fb923c; --med:#fbbf24; --low:#60a5fa; --info:#94a3b8;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--sans);background:var(--bg);color:var(--text);line-height:1.55;font-size:15px;-webkit-font-smoothing:antialiased;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(1200px 600px at 10% -10%,rgba(74,222,128,.06),transparent 60%),radial-gradient(900px 500px at 110% 10%,rgba(34,197,94,.05),transparent 55%),linear-gradient(rgba(74,222,128,.03) 1px,transparent 1px) 0 0/48px 48px,linear-gradient(90deg,rgba(74,222,128,.03) 1px,transparent 1px) 0 0/48px 48px;pointer-events:none}
.topbar{position:sticky;top:0;z-index:100;backdrop-filter:blur(14px) saturate(140%);background:rgba(10,14,12,.72);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:12px 28px;font-size:12px}
.topbar .brand{display:flex;align-items:center;gap:10px;font-family:var(--mono);letter-spacing:.06em;color:var(--green-3);text-transform:uppercase;font-size:11px}
.topbar .brand .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 rgba(74,222,128,.7);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(74,222,128,.6)}70%{box-shadow:0 0 0 10px rgba(74,222,128,0)}100%{box-shadow:0 0 0 0 rgba(74,222,128,0)}}
.topbar nav{display:flex;gap:22px}
.topbar nav a{color:var(--text-2);text-decoration:none;font-size:12px;transition:color .2s}
.topbar nav a:hover{color:var(--green-3)}
.classification{font-family:var(--mono);font-size:10px;letter-spacing:.14em;padding:4px 10px;border:1px solid var(--green-dim);border-radius:2px;color:var(--green-3);text-transform:uppercase}

.cover{position:relative;min-height:92vh;display:flex;flex-direction:column;justify-content:center;padding:60px 8vw;overflow:hidden;border-bottom:1px solid var(--line)}
.cover .scanline{position:absolute;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--green),transparent);opacity:.35;animation:scan 6s linear infinite}
@keyframes scan{0%{top:0;opacity:0}10%{opacity:.5}90%{opacity:.5}100%{top:100%;opacity:0}}
.cover .matrix{position:absolute;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.cover .matrix span{position:absolute;font-family:var(--mono);font-size:11px;color:rgba(74,222,128,.15);animation:fall linear infinite;white-space:nowrap}
@keyframes fall{0%{transform:translateY(-100%);opacity:0}10%{opacity:.6}90%{opacity:.6}100%{transform:translateY(120vh);opacity:0}}

.cover-meta{position:relative;z-index:2;display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--text-3);letter-spacing:.08em;margin-bottom:36px;text-transform:uppercase}

.banner-wrap{position:relative;display:inline-block;margin:8px 0 12px;padding:8px 0;overflow:hidden;max-width:100%;mask-image:linear-gradient(180deg,transparent 0,#000 12%,#000 88%,transparent 100%);-webkit-mask-image:linear-gradient(180deg,transparent 0,#000 12%,#000 88%,transparent 100%)}
.banner{font-family:var(--mono);font-size:clamp(7px,1.35vw,16px);line-height:1.08;color:var(--green);text-shadow:0 0 4px rgba(74,222,128,.9),0 0 12px rgba(74,222,128,.55),0 0 28px rgba(74,222,128,.28);white-space:pre;overflow-x:auto;letter-spacing:.02em;animation:flicker 8s ease-in-out infinite}
@keyframes flicker{0%,100%{opacity:1}41%{opacity:1}41.5%{opacity:.55}42%{opacity:1}77%{opacity:1}77.3%{opacity:.7}77.6%{opacity:1}}
.banner-scan{position:absolute;top:0;bottom:0;width:120px;background:linear-gradient(90deg,transparent,rgba(134,239,172,.4),transparent);filter:blur(1px);animation:bannerScan 5.5s ease-in-out infinite;pointer-events:none;mix-blend-mode:screen}
@keyframes bannerScan{0%{left:-15%}100%{left:105%}}
.banner-sub{font-family:var(--mono);font-size:11px;letter-spacing:.42em;color:var(--green-3);text-transform:uppercase;margin:0 0 32px;opacity:.85;animation:bannerSub 1.4s ease-out both}
.banner-sub::after{content:"_";margin-left:4px;color:var(--green);animation:cursor 1.1s step-end infinite}
@keyframes cursor{0%,100%{opacity:1}50%{opacity:0}}
@keyframes bannerSub{from{opacity:0;letter-spacing:1em}to{opacity:.85;letter-spacing:.42em}}

.target{position:relative;z-index:2;font-family:var(--mono);font-size:14px;color:var(--green-3);margin-bottom:14px}
.target::before{content:"▸ ";color:var(--green)}
.banner-prompt{font-family:var(--mono);font-size:12px;color:var(--text-3);margin-bottom:32px}
.banner-prompt::before{content:"$ ";color:var(--green)}
.banner-prompt .cmd{color:var(--green-3)}
.banner-prompt .arg{color:var(--text-2)}

.cover-meta-grid{position:relative;z-index:2;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:2px;border:1px solid var(--line);background:var(--line)}
.cover-meta-grid > div{background:var(--bg-2);padding:18px 22px}
.cover-meta-grid .k{font-family:var(--mono);font-size:10px;letter-spacing:.14em;color:var(--text-3);text-transform:uppercase;margin-bottom:6px}
.cover-meta-grid .v{font-size:15px;color:var(--text);font-weight:500}
.cover-meta-grid .v.mono{font-family:var(--mono);font-size:13px}

main{padding:0 8vw}
section{padding:80px 0;border-bottom:1px solid var(--line)}
section:last-child{border-bottom:0}
.section-num{font-family:var(--mono);font-size:11px;letter-spacing:.16em;color:var(--green);text-transform:uppercase;margin-bottom:14px}
h2{font-size:clamp(22px,3vw,34px);font-weight:600;letter-spacing:-.015em;margin-bottom:8px;color:#e8f5ee}
.section-sub{color:var(--text-2);font-size:14px;margin-bottom:40px;max-width:720px}

.judgment{display:grid;grid-template-columns:auto 1fr;gap:24px;padding:24px 0;border-bottom:1px solid var(--line);opacity:0;transform:translateY(12px);transition:opacity .6s,transform .6s}
.judgment.in{opacity:1;transform:translateY(0)}
.judgment:last-child{border-bottom:0}
.judgment .num{font-family:var(--mono);font-size:28px;color:var(--green-dim);font-weight:500;line-height:1}
.judgment .body{color:var(--text);font-size:15px;line-height:1.65}
.judgment .body strong{color:#fff}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);border:1px solid var(--line)}
.stat{background:var(--bg-2);padding:22px;opacity:0;transform:translateY(8px);transition:opacity .5s,transform .5s}
.stat.in{opacity:1;transform:translateY(0)}
.stat .label{font-family:var(--mono);font-size:10px;letter-spacing:.12em;color:var(--text-3);text-transform:uppercase;margin-bottom:8px}
.stat .value{font-size:26px;font-weight:600;color:#e8f5ee;line-height:1;letter-spacing:-.02em}
.stat.sev-critical .value{color:var(--crit)}
.stat.sev-high .value{color:var(--high)}
.stat.sev-medium .value{color:var(--med)}
.stat.sev-low .value{color:var(--low)}

.callout{position:relative;padding:16px 20px 16px 28px;margin:12px 0;background:linear-gradient(90deg,rgba(74,222,128,.06),transparent 60%);border-left:2px solid var(--green);font-size:14px;color:var(--text);opacity:0;transform:translateX(-8px);transition:opacity .5s,transform .5s}
.callout.in{opacity:1;transform:translateX(0)}
.callout::before{content:"▸";position:absolute;left:10px;top:16px;color:var(--green);font-size:12px}

.risk-table{width:100%;border-collapse:collapse;font-size:13px}
.risk-table th{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--text-3);padding:12px 14px;border-bottom:1px solid var(--line-2);font-weight:500}
.risk-table td{padding:14px;border-bottom:1px solid var(--line);vertical-align:middle}
.risk-table .asset{font-family:var(--mono);font-size:12px;color:var(--green-3)}
.risk-table .score{font-family:var(--mono);font-size:14px;font-weight:600;color:#e8f5ee}
.band{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:2px}
.band.critical{background:rgba(248,113,113,.12);color:var(--crit);border:1px solid rgba(248,113,113,.3)}
.band.high{background:rgba(251,146,60,.12);color:var(--high);border:1px solid rgba(251,146,60,.3)}
.band.medium{background:rgba(251,191,36,.12);color:var(--med);border:1px solid rgba(251,191,36,.3)}
.band.low{background:rgba(96,165,250,.12);color:var(--low);border:1px solid rgba(96,165,250,.3)}

.finding{border:1px solid var(--line);background:var(--bg-2);margin:14px 0;border-radius:2px;opacity:0;transform:translateY(10px);transition:opacity .5s,transform .5s}
.finding.in{opacity:1;transform:translateY(0)}
.finding-head{display:flex;align-items:center;gap:14px;padding:14px 18px;cursor:pointer;user-select:none;border-bottom:1px solid var(--line)}
.finding-head:hover{background:var(--bg-3)}
.finding-id{font-family:var(--mono);font-size:11px;color:var(--text-3);letter-spacing:.06em;min-width:56px}
.finding-title{flex:1;font-size:14px;font-weight:500;color:#e8f5ee}
.sev-pill{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:2px}
.sev-pill.critical{background:rgba(248,113,113,.12);color:var(--crit);border:1px solid rgba(248,113,113,.3)}
.sev-pill.high{background:rgba(251,146,60,.12);color:var(--high);border:1px solid rgba(251,146,60,.3)}
.sev-pill.medium{background:rgba(251,191,36,.12);color:var(--med);border:1px solid rgba(251,191,36,.3)}
.sev-pill.low{background:rgba(96,165,250,.12);color:var(--low);border:1px solid rgba(96,165,250,.3)}
.sev-pill.info{background:rgba(148,163,184,.12);color:var(--info);border:1px solid rgba(148,163,184,.3)}
.finding-body{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .4s ease,padding .3s}
.finding.open .finding-body{padding:16px 18px 20px;max-height:2400px}
.row{display:grid;grid-template-columns:140px 1fr;gap:14px;padding:8px 0;border-bottom:1px dashed var(--line);font-size:13px}
.row:last-child{border-bottom:0}
.row .k{font-family:var(--mono);font-size:11px;letter-spacing:.08em;color:var(--text-3);text-transform:uppercase}
.row .v{color:var(--text);word-break:break-word}
.evidence{font-family:var(--mono);font-size:12px;background:#080b09;border:1px solid var(--line);border-left:2px solid var(--green);padding:12px 14px;margin:8px 0;color:#b8cabe;white-space:pre-wrap;word-break:break-word;overflow-x:auto;max-height:280px;overflow-y:auto}

footer{padding:60px 8vw;border-top:1px solid var(--line);font-family:var(--mono);font-size:11px;color:var(--text-3);letter-spacing:.06em;text-transform:uppercase;display:flex;justify-content:space-between;flex-wrap:wrap;gap:16px}
@media (prefers-reduced-motion: reduce){.banner,.banner-scan,.banner-sub,.cover .scanline,.cover .matrix span{animation:none !important}}
@media print{body{background:#fff;color:#111}body::before{display:none}.topbar,.cover .matrix,.cover .scanline,.banner-scan{display:none}section{page-break-inside:avoid;padding:32px 0}.finding{page-break-inside:avoid}.evidence{background:#f4f4f4;color:#111;border-left-color:#0f7a3a}}
"""

JS = r"""
const io=new IntersectionObserver((es)=>{es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}})},{threshold:.12});
document.querySelectorAll('.judgment,.stat,.callout,.finding').forEach(el=>io.observe(el));
document.querySelectorAll('.finding-head').forEach(h=>h.addEventListener('click',()=>h.parentElement.classList.toggle('open')));
(function(){const w=document.querySelector('.cover .matrix');if(!w)return;const g='01/\\[]{}()<>|-=+*#%&';const c=Math.floor(window.innerWidth/22);for(let i=0;i<c;i++){const s=document.createElement('span');const l=6+Math.floor(Math.random()*20);let t='';for(let j=0;j<l;j++)t+=g[Math.floor(Math.random()*g.length)];s.textContent=t;s.style.left=(i*22)+'px';s.style.animationDuration=(8+Math.random()*14)+'s';s.style.animationDelay=(-Math.random()*10)+'s';w.appendChild(s)}})();
document.querySelectorAll('.stat .value[data-target]').forEach(el=>{const t=parseFloat(el.dataset.target);if(!isFinite(t)||t<1)return;const isInt=Number.isInteger(t);let c=0;const st=t/30;const iv=setInterval(()=>{c+=st;if(c>=t){c=t;clearInterval(iv)}el.textContent=isInt?Math.round(c):c.toFixed(1)},24)});
"""


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════
def _e(s) -> str:
    return html.escape(str(s) if s is not None else "")


def _sev(s) -> str:
    v = (s or "info").lower()
    return v if v in ("critical", "high", "medium", "low", "info") else "info"


def _stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _eng(root: str) -> str:
    return f"ASM-{time.strftime('%Y%m%d-%H%M')}-{root.split('.')[0].upper()[:8]}"


def _counts(findings: list[dict]) -> dict:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        c[_sev(f.get("severity"))] += 1
    return c


# ═══════════════════════════════════════════════════════════════════
# SECTIONS
# ═══════════════════════════════════════════════════════════════════
def _r_cover(target, findings, eng_id, version):
    c = _counts(findings)
    return f"""
<header class="cover">
  <div class="scanline"></div>
  <div class="matrix"></div>
  <div class="cover-meta">
    <span>Technical Security Assessment</span>
    <span>Classification · Confidential</span>
  </div>
  <div class="banner-wrap">
    <pre class="banner" aria-label="ATOMIC">{_e(BANNER_ART)}</pre>
    <div class="banner-scan"></div>
  </div>
  <div class="banner-sub">Reconnaissance · Assessment · Report</div>
  <div class="target">{_e(target.get('root_domain',''))}</div>
  <div class="banner-prompt"><span class="cmd">atomic</span> <span class="arg">--target {_e(target.get('root_domain',''))} --engagement {_e(eng_id)}</span></div>
  <div class="cover-meta-grid">
    <div><div class="k">Engagement</div><div class="v mono">{_e(eng_id)}</div></div>
    <div><div class="k">Generated</div><div class="v mono">{_e(_stamp())}</div></div>
    <div><div class="k">Version</div><div class="v mono">{_e(version)}</div></div>
    <div><div class="k">Findings</div><div class="v mono">{len(findings)}</div></div>
    <div><div class="k">Critical</div><div class="v mono" style="color:var(--crit)">{c['critical']}</div></div>
    <div><div class="k">High</div><div class="v mono" style="color:var(--high)">{c['high']}</div></div>
  </div>
</header>
"""


def _r_judgments(findings):
    ch = [f for f in findings if _sev(f.get("severity")) in ("critical", "high")]
    ch.sort(key=lambda f: (0 if _sev(f["severity"]) == "critical" else 1))
    items, seen = [], set()
    for f in ch:
        cat = f.get("category", "")
        if cat in seen:
            continue
        seen.add(cat)
        title = _e(f.get("title", ""))
        ev = (f.get("evidence", "") or "").split("\n")[0][:180]
        body = f"<strong>{title}</strong>"
        if ev:
            body += f" — <span style='color:var(--text-2)'>{_e(ev)}</span>"
        items.append(f"<div class='judgment'><div class='num'>{len(items)+1:02d}</div><div class='body'>{body}</div></div>")
        if len(items) >= 5:
            break
    if not items:
        items.append("<div class='judgment'><div class='num'>01</div><div class='body'>No critical or high-severity findings were confirmed during this engagement.</div></div>")
    return f"""
<section id="judgments">
  <div class="section-num">Section 01 · Key Judgments</div>
  <h2>Executive Summary</h2>
  <p class="section-sub">Findings that most materially change risk exposure for the in-scope estate.</p>
  {''.join(items)}
</section>
"""


def _r_exposure(target, data, findings):
    subs = data.get("subdomains") or {}
    ports = data.get("ports") or {}
    eps = data.get("endpoints") or {}
    dirs = data.get("directories") or {}
    hf = data.get("hidden_files") or {}
    logins = data.get("logins") or {}
    c = _counts(findings)

    def s(label, val, cls=""):
        return f"<div class='stat {cls}'><div class='label'>{_e(label)}</div><div class='value' data-target='{int(val)}'>{int(val)}</div></div>"

    return f"""
<section id="exposure">
  <div class="section-num">Section 02 · Exposure Summary</div>
  <h2>Surface Inventory</h2>
  <p class="section-sub">Observed public surface and finding distribution for the target estate.</p>
  <div class="stats">
    {s("Subdomains", subs.get("count", 0))}
    {s("Open Ports", len(ports.get("open", [])))}
    {s("Endpoints", len(eps.get("endpoints", [])))}
    {s("Directories", dirs.get("found", 0))}
    {s("Hidden Files", hf.get("found", 0))}
    {s("Login Panels", logins.get("found", 0))}
    {s("Critical", c["critical"], "sev-critical")}
    {s("High", c["high"], "sev-high")}
    {s("Medium", c["medium"], "sev-medium")}
    {s("Low", c["low"], "sev-low")}
  </div>
</section>
"""


def _r_capabilities(findings):
    templates = {
        "sqli": "Execute arbitrary SQL against {param} on {url}",
        "xss": "Inject script into {param} on {url}",
        "lfi": "Read arbitrary server files via {param} on {url}",
        "rfi": "Include remote files via {param} on {url}",
        "ssrf": "Pivot to internal services via {param} on {url}",
        "ssti": "Execute server-side template code via {param} on {url}",
        "xxe": "Read local files via XML external entities on {url}",
        "command_injection": "Execute shell commands via {param} on {url}",
        "nosql": "Bypass login via NoSQL injection on {url}",
        "crlf": "Split HTTP responses via {param} on {url}",
        "open_redirect": "Redirect users to arbitrary destinations via {param} on {url}",
        "exposed_config": "Read production configuration material from {url}",
        "exposed_secret": "Obtain private key material from {url}",
        "hidden_database": "Reach a data store administrative interface at {url}",
        "exposed_database": "Enumerate records from an unauthenticated data store at {url}",
        "exposed_bucket": "Enumerate cloud storage contents at {url}",
        "secrets": "Retrieve hardcoded credentials from client-side assets at {url}",
        "takeover": "Claim and control the subdomain {url}",
        "brute_feasible": "Attempt credential guessing without rate-limit friction against {url}",
        "cors": "Read cross-origin authenticated data via {url}",
        "graphql": "Query the exposed GraphQL schema at {url}",
        "jwt": "Forge JSON Web Tokens for {url}",
    }
    priority = ["sqli", "command_injection", "ssti", "lfi", "ssrf", "nosql", "xxe",
                "hidden_database", "exposed_database", "exposed_bucket", "exposed_secret",
                "exposed_config", "secrets", "takeover", "jwt", "brute_feasible",
                "cors", "graphql", "open_redirect", "xss", "crlf"]
    callouts = []
    for cat in priority:
        m = [f for f in findings if f.get("category") == cat and _sev(f.get("severity")) in ("critical", "high", "medium")]
        for f in m[:1]:
            tpl = templates.get(cat, f.get("title", ""))
            text = tpl.format(url=f.get("url", ""),
                              param=(f.get("extra") or {}).get("param", "the affected parameter"))
            callouts.append(f"<div class='callout'>{_e(text)}</div>")
            if len(callouts) >= 8:
                break
        if len(callouts) >= 8:
            break
    if not callouts:
        callouts.append("<div class='callout'>No confirmed attacker capability was demonstrated in this engagement.</div>")
    return f"""
<section id="capabilities">
  <div class="section-num">Section 03 · Demonstrated Capability</div>
  <h2>What a stranger can do today</h2>
  <p class="section-sub">Confirmed actions available to an unauthenticated attacker, given only findings from this engagement.</p>
  <div class="callouts">{''.join(callouts)}</div>
</section>
"""


def _r_risk(findings):
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    by_asset: dict[str, list] = {}
    for f in findings:
        asset = (f.get("extra") or {}).get("asset") or f.get("url") or "target"
        by_asset.setdefault(asset, []).append(f)

    rows = []
    for asset, items in by_asset.items():
        top = max((_sev(i["severity"]) for i in items), key=lambda x: weights[x])
        confirmed = sum(1 for i in items if _sev(i["severity"]) != "info")
        score = min(10.0, round(weights[top] * 4 + confirmed * 0.5, 1))
        band = "critical" if score >= 8.5 else "high" if score >= 6.5 else "medium" if score >= 4 else "low" if score >= 2 else "info"
        rows.append((score, asset, top, confirmed, band))
    rows.sort(reverse=True)

    body = ""
    for score, asset, sev, n, band in rows[:20]:
        body += (
            f"<tr><td class='asset'>{_e(asset[:60])}</td>"
            f"<td><span class='band {band}'>{_e(band)}</span></td>"
            f"<td class='score'>{score:.1f} / 10</td>"
            f"<td>{n}</td>"
            f"<td>{_e(sev)}</td></tr>"
        )
    if not body:
        body = "<tr><td colspan='5' style='color:var(--text-3)'>No assets scored.</td></tr>"

    return f"""
<section id="risk">
  <div class="section-num">Section 04 · Risk Register</div>
  <h2>Per-Asset Risk</h2>
  <p class="section-sub">Composite score derived from highest severity, confirmed-finding count, and exposure.</p>
  <table class="risk-table">
    <thead><tr><th>Asset</th><th>Band</th><th>Score</th><th>Confirmed</th><th>Top</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</section>
"""


def _r_findings(findings):
    priority = ["critical", "high", "medium", "low", "info"]
    by_sev: dict[str, list] = {s: [] for s in priority}
    for f in findings:
        by_sev[_sev(f.get("severity"))].append(f)
    cards = []
    idx = 1
    for sev in priority:
        for f in by_sev[sev]:
            fid = f"F-{idx:03d}"
            idx += 1
            ev = _e(f.get("evidence", "") or "")
            rem = _e(f.get("remediation", "") or "")
            extra = f.get("extra") or {}
            extra_lines = "".join(
                f"<div class='row'><div class='k'>{_e(k)}</div><div class='v'>{_e(v)}</div></div>"
                for k, v in extra.items()
            )
            cards.append(f"""
<div class="finding">
  <div class="finding-head">
    <span class="finding-id">{fid}</span>
    <span class="finding-title">{_e(f.get('title', ''))}</span>
    <span class="sev-pill {sev}">{sev}</span>
  </div>
  <div class="finding-body">
    <div class="row"><div class="k">Category</div><div class="v">{_e(f.get('category', ''))}</div></div>
    <div class="row"><div class="k">Asset</div><div class="v"><code>{_e(f.get('url', '') or '—')}</code></div></div>
    {extra_lines}
    {f'<div class="row"><div class="k">Remediation</div><div class="v">{rem}</div></div>' if rem else ''}
    {f'<div class="row"><div class="k">Evidence</div><div class="v"><pre class="evidence">{ev}</pre></div></div>' if ev else ''}
  </div>
</div>""")
    if not cards:
        cards.append("<p style='color:var(--text-3)'>No findings.</p>")
    return f"""
<section id="findings">
  <div class="section-num">Section 05 · Findings Register</div>
  <h2>All Findings</h2>
  <p class="section-sub">Click any row to expand proof and remediation.</p>
  {''.join(cards)}
</section>
"""


# ═══════════════════════════════════════════════════════════════════
# MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════
def write_reports(target: dict, data: dict, findings: list, out_dir: str,
                  version: str = "3.1.0") -> dict:
    """Write JSON + HTML report. Returns paths."""
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.join(out_dir, f"{target['root_domain']}_{ts}")

    # JSON (raw)
    json_path = base + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "generated": ts,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
            "data": data,
        }, f, indent=2, default=str)

    # HTML
    eng_id = _eng(target["root_domain"])
    fd = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
    c = _counts(fd)

    html_doc = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATOMIC — {_e(target['root_domain'])} — {_e(eng_id)}</title>
<style>{CSS}</style>
</head><body>
<div class="topbar">
  <div class="brand"><span class="dot"></span>atomic · {_e(target['root_domain'])}</div>
  <nav>
    <a href="#judgments">Judgments</a>
    <a href="#exposure">Exposure</a>
    <a href="#capabilities">Capability</a>
    <a href="#risk">Risk</a>
    <a href="#findings">Findings</a>
  </nav>
  <span class="classification">Confidential</span>
</div>
{_r_cover(target, fd, eng_id, version)}
<main>
{_r_judgments(fd)}
{_r_exposure(target, data, fd)}
{_r_capabilities(fd)}
{_r_risk(fd)}
{_r_findings(fd)}
</main>
<footer>
  <span>ATOMIC v{_e(version)} · {_e(eng_id)}</span>
  <span>{len(fd)} findings · {c['critical']}C · {c['high']}H · {c['medium']}M · {c['low']}L · {c['info']}I</span>
  <span>Generated {_e(_stamp())}</span>
</footer>
<script>{JS}</script>
</body></html>"""

    html_path = base + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    return {
        "json": json_path,
        "html": html_path,
        "summary": f"{len(fd)} findings · {c['critical']}C · {c['high']}H · {c['medium']}M · {c['low']}L · {c['info']}I",
    }
