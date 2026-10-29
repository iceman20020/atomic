"""
playbook.py — template engine + embedded templates.

Templates are dicts. Engine sends the request, applies matchers, emits
findings. A matcher can be status, header, body, word, or regex. Templates
group by category. External YAML templates from atomic/data/templates/ are
loaded on top of embedded ones.

Write a new template by adding to TEMPLATES. No YAML required.
"""
from __future__ import annotations
import asyncio
import os
import re
import json
from typing import Any, Optional

from .spine import (
    HttpClient, make_finding, Finding, header_dict, resp_text, body_snippet,
    resp_len, resp_hash, urljoin,
)
from .armory import DATABASE_UI_PATHS, DATABASE_SUCCESS_MARKERS


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE LIST
# ═══════════════════════════════════════════════════════════════════
# Schema:
# {
#   "id": "unique-id",
#   "name": "Human name",
#   "severity": "info|low|medium|high|critical",
#   "category": "exposed_config|exposed_admin|exposed_database|...",
#   "method": "GET|POST",
#   "path": "/path" or list of paths,
#   "headers": {},
#   "body": None,
#   "match_status": [200, 302],          # optional; default [200]
#   "match_words": ["word1", "word2"],   # optional; ALL must appear
#   "match_any_words": ["w1","w2"],      # optional; ANY must appear
#   "match_regex": "pattern",            # optional
#   "not_words": ["word"],               # optional; NONE must appear
#   "extract": "field_name",             # optional; 1 capture group name
#   "remediation": "short hint",
# }
TEMPLATES: list[dict] = [

    # ─── exposed config files ──────────────────────────────────────
    {"id": "env-file", "name": "Exposed .env file", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/.env",
     "match_status": [200], "match_regex": r"(?:DB_|APP_|AWS_|SECRET_|API_|REDIS_|MAIL_)\w+\s*=",
     "remediation": "Remove file from webroot; rotate any exposed credentials."},
    {"id": "env-prod", "name": "Exposed .env.production", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/.env.production",
     "match_regex": r"\w+=\S+"},
    {"id": "git-head", "name": "Exposed .git/HEAD", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/.git/HEAD",
     "match_status": [200], "match_words": ["ref:"],
     "remediation": "Block .git directory; remove from webroot."},
    {"id": "git-config", "name": "Exposed .git/config", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/.git/config",
     "match_words": ["[core]"]},
    {"id": "svn-entries", "name": "Exposed .svn/entries", "severity": "medium",
     "category": "exposed_config", "method": "GET", "path": "/.svn/entries",
     "match_regex": r"^\d+"},
    {"id": "ds-store", "name": "Exposed .DS_Store", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/.DS_Store",
     "match_status": [200], "match_words": ["Bud1"]},
    {"id": "htaccess", "name": "Exposed .htaccess", "severity": "medium",
     "category": "exposed_config", "method": "GET", "path": "/.htaccess",
     "match_words": ["<IfModule"], "match_status": [200]},
    {"id": "htpasswd", "name": "Exposed .htpasswd", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/.htpasswd",
     "match_regex": r"^[\w\-]+:\$"},
    {"id": "wp-config-bak", "name": "Exposed wp-config.php backup", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/wp-config.php.bak",
     "match_words": ["DB_PASSWORD"]},
    {"id": "config-php-bak", "name": "Exposed config.php backup", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/config.php.bak",
     "match_regex": r"(?:DB_|mysql_|mysqli_|PDO)"},
    {"id": "web-config-bak", "name": "Exposed web.config backup", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/web.config.bak",
     "match_words": ["<configuration>"]},
    {"id": "appsettings", "name": "Exposed appsettings.json", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/appsettings.json",
     "match_regex": r'"(?:ConnectionStrings|Logging|AllowedHosts)"'},
    {"id": "appsettings-dev", "name": "Exposed appsettings.Development.json",
     "severity": "critical", "category": "exposed_config", "method": "GET",
     "path": "/appsettings.Development.json",
     "match_regex": r'"(?:ConnectionStrings|Logging)"'},
    {"id": "application-properties", "name": "Exposed application.properties",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/application.properties",
     "match_regex": r"spring\.|server\.|datasource"},
    {"id": "application-yml", "name": "Exposed application.yml",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/application.yml",
     "match_regex": r"spring:|server:|datasource"},
    {"id": "composer-json", "name": "Exposed composer.json", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/composer.json",
     "match_words": ['"require"']},
    {"id": "composer-lock", "name": "Exposed composer.lock", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/composer.lock",
     "match_words": ['"packages"']},
    {"id": "package-json", "name": "Exposed package.json", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/package.json",
     "match_words": ['"dependencies"', '"version"']},
    {"id": "package-lock", "name": "Exposed package-lock.json", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/package-lock.json",
     "match_words": ['"lockfileVersion"']},
    {"id": "yarn-lock", "name": "Exposed yarn.lock", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/yarn.lock",
     "match_words": ["# THIS IS AN AUTOGENERATED FILE"]},
    {"id": "dockerfile", "name": "Exposed Dockerfile", "severity": "medium",
     "category": "exposed_config", "method": "GET", "path": "/Dockerfile",
     "match_regex": r"^FROM\s"},
    {"id": "docker-compose", "name": "Exposed docker-compose.yml", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/docker-compose.yml",
     "match_regex": r"services:\s*$|^\s+image:"},
    {"id": "makefile", "name": "Exposed Makefile", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/Makefile",
     "match_regex": r"^[\w\-]+\s*:"},
    {"id": "requirements-txt", "name": "Exposed requirements.txt", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/requirements.txt",
     "match_regex": r"^[\w\-]+\s*(?:==|>=|~=|<=)"},
    {"id": "id-rsa", "name": "Exposed SSH private key", "severity": "critical",
     "category": "exposed_secret", "method": "GET", "path": "/id_rsa",
     "match_words": ["-----BEGIN"], "match_status": [200]},
    {"id": "id-rsa-ssh-dir", "name": "Exposed .ssh/id_rsa", "severity": "critical",
     "category": "exposed_secret", "method": "GET", "path": "/.ssh/id_rsa",
     "match_words": ["PRIVATE KEY"]},
    {"id": "id-ed25519", "name": "Exposed SSH ed25519 key", "severity": "critical",
     "category": "exposed_secret", "method": "GET", "path": "/id_ed25519",
     "match_words": ["PRIVATE KEY"]},

    # ─── swagger / openapi ────────────────────────────────────────
    {"id": "swagger-json", "name": "Exposed Swagger JSON", "severity": "medium",
     "category": "exposed_api_doc", "method": "GET", "path": "/swagger.json",
     "match_regex": r'"(?:swagger|openapi)"\s*:\s*"'},
    {"id": "openapi-json", "name": "Exposed OpenAPI JSON", "severity": "medium",
     "category": "exposed_api_doc", "method": "GET", "path": "/openapi.json",
     "match_regex": r'"openapi"\s*:\s*"'},
    {"id": "v2-api-docs", "name": "Exposed v2/api-docs", "severity": "medium",
     "category": "exposed_api_doc", "method": "GET", "path": "/v2/api-docs",
     "match_regex": r'"swagger"\s*:\s*"'},
    {"id": "v3-api-docs", "name": "Exposed v3/api-docs", "severity": "medium",
     "category": "exposed_api_doc", "method": "GET", "path": "/v3/api-docs",
     "match_regex": r'"openapi"\s*:\s*"'},
    {"id": "swagger-ui", "name": "Swagger UI exposed", "severity": "low",
     "category": "exposed_api_doc", "method": "GET", "path": "/swagger-ui.html",
     "match_words": ["Swagger UI"]},
    {"id": "swagger-ui-idx", "name": "Swagger UI index exposed", "severity": "low",
     "category": "exposed_api_doc", "method": "GET", "path": "/swagger-ui/index.html",
     "match_words": ["Swagger"]},

    # ─── actuator ────────────────────────────────────────────────
    {"id": "actuator", "name": "Spring Boot Actuator root", "severity": "medium",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator",
     "match_regex": r'"_links"|"self"'},
    {"id": "actuator-env", "name": "Actuator /env exposed", "severity": "high",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator/env",
     "match_regex": r'"(?:propertySources|activeProfiles)"'},
    {"id": "actuator-heapdump", "name": "Actuator /heapdump exposed", "severity": "critical",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator/heapdump",
     "match_status": [200], "not_words": ["Whitelabel", "404", "not found"]},
    {"id": "actuator-mappings", "name": "Actuator /mappings exposed", "severity": "medium",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator/mappings",
     "match_regex": r'"(?:mappings|dispatcherServlets)"'},
    {"id": "actuator-beans", "name": "Actuator /beans exposed", "severity": "medium",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator/beans",
     "match_regex": r'"(?:beans|context)"'},
    {"id": "actuator-threaddump", "name": "Actuator /threaddump exposed", "severity": "medium",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator/threaddump",
     "match_regex": r'"(?:threads|threadName)"'},
    {"id": "actuator-httptrace", "name": "Actuator /httptrace exposed", "severity": "medium",
     "category": "exposed_actuator", "method": "GET", "path": "/actuator/httptrace",
     "match_regex": r'"(?:traces|request|response)"'},

    # ─── debug / admin ────────────────────────────────────────────
    {"id": "phpinfo", "name": "phpinfo() exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/phpinfo.php",
     "match_words": ["PHP Version", "php.ini"]},
    {"id": "server-status", "name": "Apache server-status exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/server-status",
     "match_words": ["Apache Server Status"]},
    {"id": "server-info", "name": "Apache server-info exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/server-info",
     "match_words": ["Apache Server Information"]},
    {"id": "nginx-status", "name": "nginx stub_status exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/nginx_status",
     "match_words": ["Active connections"]},
    {"id": "debug-vars", "name": "Go debug/vars exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/debug/vars",
     "match_regex": r'"(?:cmdline|memstats)"'},
    {"id": "debug-pprof", "name": "Go debug/pprof exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/debug/pprof/",
     "match_words": ["Types of profiles available", "goroutine"]},

    # ─── database interfaces ─────────────────────────────────────
    {"id": "phpmyadmin", "name": "phpMyAdmin interface", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/phpmyadmin/",
     "match_words": ["phpMyAdmin"]},
    {"id": "adminer", "name": "Adminer interface", "severity": "high",
     "category": "exposed_database", "method": "GET", "path": "/adminer.php",
     "match_words": ["Adminer"]},
    {"id": "mongo-express", "name": "Mongo-Express interface", "severity": "critical",
     "category": "exposed_database", "method": "GET", "path": "/mongo-express/",
     "match_words": ["Mongo Express"]},
    {"id": "redis-commander", "name": "Redis Commander interface", "severity": "critical",
     "category": "exposed_database", "method": "GET", "path": "/redis-commander/",
     "match_words": ["Redis Commander"]},
    {"id": "elasticsearch", "name": "Elasticsearch HTTP interface", "severity": "critical",
     "category": "exposed_database", "method": "GET", "path": "/",
     "match_regex": r'"cluster_name".*"tagline".*"You Know, for Search"'},
    {"id": "es-cat-indices", "name": "Elasticsearch indices enumerable", "severity": "critical",
     "category": "exposed_database", "method": "GET", "path": "/_cat/indices",
     "match_regex": r"^\w+\s+\w+\s+\d+", "match_status": [200]},
    {"id": "couchdb", "name": "CouchDB welcome", "severity": "high",
     "category": "exposed_database", "method": "GET", "path": "/",
     "match_regex": r'"couchdb"\s*:\s*"Welcome"'},
    {"id": "couchdb-all-dbs", "name": "CouchDB databases enumerable", "severity": "critical",
     "category": "exposed_database", "method": "GET", "path": "/_all_dbs",
     "match_status": [200], "match_regex": r'^\['},
    {"id": "couchdb-utils", "name": "CouchDB Fauxton UI exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/_utils/",
     "match_words": ["Fauxton"]},
    {"id": "prometheus-graph", "name": "Prometheus UI exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/graph",
     "match_words": ["Prometheus", "Graph"]},
    {"id": "prometheus-api", "name": "Prometheus API exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/api/v1/targets",
     "match_regex": r'"status"\s*:\s*"success"'},
    {"id": "influxdb-query", "name": "InfluxDB query endpoint", "severity": "high",
     "category": "exposed_database", "method": "GET",
     "path": "/query?q=SHOW+DATABASES",
     "match_regex": r'"results"'},
    {"id": "kibana", "name": "Kibana UI exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/app/kibana",
     "match_words": ["kibana", "Kibana"]},
    {"id": "grafana", "name": "Grafana UI exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/login",
     "match_words": ["grafanaBootData", "Grafana"]},
    {"id": "solr", "name": "Solr admin exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/solr/",
     "match_words": ["Solr Admin", "solr"]},
    {"id": "arangodb", "name": "ArangoDB web UI exposed", "severity": "high",
     "category": "exposed_database", "method": "GET", "path": "/_db/_system/_admin/aardvark/index.html",
     "match_words": ["ArangoDB", "aardvark"]},
    {"id": "neo4j-browser", "name": "Neo4j browser exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/browser/",
     "match_words": ["Neo4j", "browser"]},
    {"id": "clickhouse-http", "name": "ClickHouse HTTP reachable", "severity": "high",
     "category": "exposed_database", "method": "GET",
     "path": "/?query=SELECT%20version()",
     "match_status": [200], "not_words": ["<html", "not found"]},

    # ─── bucket ──────────────────────────────────────────────────
    {"id": "s3-listable", "name": "S3 bucket listable", "severity": "high",
     "category": "exposed_bucket", "method": "GET",
     "path": "/?list-type=2",
     "match_words": ["<ListBucketResult"]},

    # ─── ci / devops ─────────────────────────────────────────────
    {"id": "jenkins", "name": "Jenkins dashboard exposed", "severity": "medium",
     "category": "exposed_admin", "method": "GET", "path": "/",
     "match_words": ["Jenkins", "Dashboard"]},
    {"id": "jenkins-script", "name": "Jenkins script console exposed", "severity": "critical",
     "category": "exposed_admin", "method": "GET", "path": "/script",
     "match_words": ["Groovy script", "Script Console"]},
    {"id": "gitlab", "name": "GitLab login exposed", "severity": "low",
     "category": "exposed_admin", "method": "GET", "path": "/users/sign_in",
     "match_words": ["GitLab", "sign in"]},
    {"id": "grafana-login", "name": "Grafana login exposed", "severity": "low",
     "category": "exposed_admin", "method": "GET", "path": "/login",
     "match_words": ["grafana", "login"]},
    {"id": "kibana-login", "name": "Kibana login exposed", "severity": "low",
     "category": "exposed_admin", "method": "GET", "path": "/login",
     "match_words": ["Kibana", "login"]},

    # ─── web shell / backdoor ────────────────────────────────────
    {"id": "webshell-c99", "name": "Possible c99 web shell", "severity": "critical",
     "category": "webshell", "method": "GET", "path": "/c99.php",
     "match_words": ["c99shell", "c99madShell"]},
    {"id": "webshell-r57", "name": "Possible r57 web shell", "severity": "critical",
     "category": "webshell", "method": "GET", "path": "/r57.php",
     "match_words": ["r57shell", "r57"]},
    {"id": "webshell-wso", "name": "Possible WSO web shell", "severity": "critical",
     "category": "webshell", "method": "GET", "path": "/wso.php",
     "match_words": ["wsoEx", "WSO 2."]},

    # ─── specific CVE fingerprint hints ──────────────────────────
    {"id": "wp-json-users", "name": "WordPress REST user enumeration",
     "severity": "medium", "category": "wordpress", "method": "GET",
     "path": "/wp-json/wp/v2/users",
     "match_regex": r'"(?:id|slug|name)"\s*:'},
    {"id": "wp-xmlrpc", "name": "WordPress xmlrpc.php enabled", "severity": "low",
     "category": "wordpress", "method": "GET", "path": "/xmlrpc.php",
     "match_words": ["XML-RPC server accepts POST requests only"]},
    {"id": "wp-readme", "name": "WordPress readme.html leaks version",
     "severity": "low", "category": "wordpress", "method": "GET",
     "path": "/readme.html", "match_words": ["WordPress"]},
    {"id": "drupal-changelog", "name": "Drupal CHANGELOG.txt exposed",
     "severity": "low", "category": "drupal", "method": "GET",
     "path": "/CHANGELOG.txt", "match_words": ["Drupal "]},
    {"id": "joomla-manifest", "name": "Joomla manifest exposes version",
     "severity": "low", "category": "joomla", "method": "GET",
     "path": "/administrator/manifests/files/joomla.xml",
     "match_words": ["<version>"]},
    {"id": "laravel-debug", "name": "Laravel debug mode (IGNITION/Whoops)",
     "severity": "high", "category": "framework", "method": "GET",
     "path": "/_ignition/health-check",
     "match_status": [200], "match_words": ["can_execute_commands"]},
    {"id": "rails-debug", "name": "Rails exception page exposed",
     "severity": "medium", "category": "framework", "method": "GET",
     "path": "/rails/info/properties",
     "match_words": ["Rails version"]},
    {"id": "spring-boot-error", "name": "Spring Boot error page leaks",
     "severity": "low", "category": "framework", "method": "GET",
     "path": "/error", "match_words": ["Whitelabel Error Page"]},
]


# ═══════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════
def _match_template(tpl: dict, status: int, headers: dict, body: str) -> tuple[bool, str]:
    """Return (matched, evidence)."""
    # status
    match_status = tpl.get("match_status") or [200]
    if status not in match_status:
        return False, ""

    # negative words
    for w in tpl.get("not_words") or []:
        if w.lower() in body.lower():
            return False, ""

    # required words (all must appear)
    evidence_parts = []
    for w in tpl.get("match_words") or []:
        if w.lower() not in body.lower():
            return False, ""
        evidence_parts.append(f"word:{w!r}")

    # any-of words
    any_words = tpl.get("match_any_words") or []
    if any_words:
        if not any(w.lower() in body.lower() for w in any_words):
            return False, ""
        evidence_parts.append("any-of-matched")

    # regex
    if rx := tpl.get("match_regex"):
        m = re.search(rx, body, re.I | re.M)
        if not m:
            return False, ""
        evidence_parts.append(f"regex:{m.group(0)[:120]}")

    return True, " | ".join(evidence_parts)


async def _run_template(client: HttpClient, base_url: str, tpl: dict) -> Optional[Finding]:
    path = tpl["path"]
    if isinstance(path, list):
        paths = path
    else:
        paths = [path]
    for p in paths:
        url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
        r = await client.get(url, headers=tpl.get("headers") or {})
        if r is None:
            continue
        body = resp_text(r)
        headers = header_dict(r)
        matched, evidence = _match_template(tpl, r.status_code, headers, body)
        if matched:
            return make_finding(
                category=tpl.get("category", "template"),
                title=tpl["name"],
                severity=tpl.get("severity", "info"),
                url=url,
                evidence=f"{evidence} | body[{resp_len(r)}B]: {body_snippet(r, 200)}",
                extra={"template_id": tpl["id"], "status": r.status_code},
                remediation=tpl.get("remediation", ""),
            )
    return None


async def run(client: HttpClient, base_url: str, extra_templates: list[dict] | None = None) -> list[Finding]:
    """Run all templates. Returns findings."""
    templates = list(TEMPLATES)
    if extra_templates:
        templates.extend(extra_templates)

    # group templates by path prefix so we don't re-fetch the base page
    tasks = [_run_template(client, base_url, tpl) for tpl in templates]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings = []
    for r in results:
        if isinstance(r, Finding):
            findings.append(r)
    return findings


# ═══════════════════════════════════════════════════════════════════
# EXTERNAL YAML LOADER (optional)
# ═══════════════════════════════════════════════════════════════════
def load_external_templates(dir_path: str) -> list[dict]:
    """Load YAML templates from a directory (if yaml is installed)."""
    try:
        import yaml
    except Exception:
        return []
    out = []
    if not os.path.isdir(dir_path):
        return out
    for fn in os.listdir(dir_path):
        if not fn.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(dir_path, fn), encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                out.append(data)
            elif isinstance(data, list):
                out.extend(data)
        except Exception:
            continue
    return out
