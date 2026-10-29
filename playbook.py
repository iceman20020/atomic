"""
playbook.py — template engine + embedded templates.

Templates are dicts. Engine sends the request, applies matchers, emits
findings. A matcher can be status, header, body, word, or regex. Templates
group by category. External YAML templates from atomic/data/templates/ are
loaded on top of embedded ones.

Matcher discipline:
  - `fail_words`      — if ANY appears, the finding is discarded.
                        Catches WAF blocks, default server pages, 404/SPA
                        catches, framework error pages.
  - `success_words`   — if provided, at least ONE must appear (soft
                        confirmation). Combined with match_words /
                        match_any_words / match_regex via AND.
  - `not_words`       — legacy alias; merged into fail_words at compile.
  - A global default_fail list runs on every template, on top of the
    per-template fail_words, to reject the universal false positives.

Schema:
{
  "id": "unique-id",
  "name": "Human name",
  "severity": "info|low|medium|high|critical",
  "category": "exposed_config|exposed_admin|exposed_database|...",
  "method": "GET|POST",
  "path": "/path" or list of paths,
  "headers": {},
  "body": None,

  # Hard requirements (all must pass):
  "match_status":     [200, 302],
  "match_words":      ["word1", "word2"],     # all must appear
  "match_any_words":  ["w1","w2"],            # at least one must appear
  "match_regex":      "pattern",
  "success_words":    ["w1","w2"],            # at least one must appear

  # Negative signals (any hit = discard):
  "fail_words":       ["word"],               # any hit discards
  "not_words":        ["word"],               # legacy alias → fail_words

  # Optional guards:
  "expect_content_type": "json|html|text|xml|octet",
  "max_len":  200000,                         # discard if larger
  "min_len":  8,                              # discard if smaller
  "extract":  "field_name",
  "remediation": "short hint",
}
"""
from __future__ import annotations
import asyncio
import os
import re
from typing import Any, Optional

from .spine import (
    HttpClient, make_finding, Finding, header_dict, resp_text, body_snippet,
    resp_len, resp_hash, urljoin,
)
from .armory import DATABASE_UI_PATHS, DATABASE_SUCCESS_MARKERS


# ═══════════════════════════════════════════════════════════════════
# GLOBAL FAIL WORDS — applied to every template before per-template
# failures. These are universal false-positive sources.
# ═══════════════════════════════════════════════════════════════════
DEFAULT_FAIL_WORDS = [
    # universal 404 / SPA catches
    "404 not found", "page not found", "the page you are looking for",
    "we can't find that page", "this page doesn't exist",
    "no such file or directory", "there isn't a github pages site here",
    "the requested url was not found",
    "the page you requested could not be found",
    "the resource you are looking for has been removed",
    "the page you are looking for could not be found",
    "sorry, this page isn't available",
    "sorry, this page doesn't exist",
    # WAF block pages
    "attention required! | cloudflare", "access denied | cloudflare",
    "cloudflare ray id", "request blocked", "the requested url was rejected",
    "your request has been blocked", "you have been blocked",
    "web application firewall", "mod_security",
    "your ip has been blocked",
    "please verify you are a human", "checking your browser",
    "captcha required", "unusual traffic from your",
    "403 forbidden", "401 unauthorized",
    # default web server pages
    "welcome to nginx", "iis windows server",
    "apache2 ubuntu default page", "apache http server test page",
    "test page for the apache http server",
    "the apache2 default configuration",
    "if you see this page, the nginx web server is successfully installed",
    "site not configured", "this domain is parked",
    "this site is under construction", "coming soon page",
    "hostgator default", "cpanel default page",
    # framework error pages
    "whitelabel error page", "django technical 404",
    "django page not found", "rails error", "there was an error",
    "internal server error", "502 bad gateway", "503 service unavailable",
    "504 gateway timeout",
    "something went wrong", "an unexpected error occurred",
    "error 404", "error 403", "error 500",
]


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE LIST
# ═══════════════════════════════════════════════════════════════════
TEMPLATES: list[dict] = [

    # ═══════════════════════════════════════════════════════════════
    # EXPOSED CONFIG FILES
    # ═══════════════════════════════════════════════════════════════
    {"id": "env-file", "name": "Exposed .env file", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/.env",
     "match_status": [200],
     "success_words": ["DB_", "APP_", "AWS_", "SECRET_", "API_", "REDIS_", "MAIL_"],
     "match_regex": r"(?:DB_|APP_|AWS_|SECRET_|API_|REDIS_|MAIL_)\w+\s*=",
     "fail_words": ["<html", "<!doctype html", "application/json", "<error"],
     "expect_content_type": "text",
     "remediation": "Remove file from webroot; rotate any exposed credentials."},

    {"id": "env-prod", "name": "Exposed .env.production", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/.env.production",
     "match_regex": r"\w+=\S+",
     "success_words": ["DB_", "APP_", "AWS_", "SECRET_", "API_"],
     "fail_words": ["<html", "<!doctype", "<error"],
     "expect_content_type": "text"},

    {"id": "git-head", "name": "Exposed .git/HEAD", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/.git/HEAD",
     "match_status": [200], "match_words": ["ref:"],
     "success_words": ["refs/heads", "ref:"],
     "fail_words": ["<html", "<!doctype", "<error"],
     "remediation": "Block .git directory; remove from webroot."},

    {"id": "git-config", "name": "Exposed .git/config", "severity": "high",
     "category": "exposed_config", "method": "GET", "path": "/.git/config",
     "match_words": ["[core]"],
     "success_words": ["[core]", "[remote"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "svn-entries", "name": "Exposed .svn/entries", "severity": "medium",
     "category": "exposed_config", "method": "GET", "path": "/.svn/entries",
     "match_regex": r"^\d+",
     "success_words": ["dir", "file"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "ds-store", "name": "Exposed .DS_Store", "severity": "low",
     "category": "exposed_config", "method": "GET", "path": "/.DS_Store",
     "match_status": [200], "match_words": ["Bud1"],
     "success_words": ["Bud1"],
     "fail_words": ["<html", "<!doctype", "text/plain"]},

    {"id": "htaccess", "name": "Exposed .htaccess", "severity": "medium",
     "category": "exposed_config", "method": "GET", "path": "/.htaccess",
     "match_words": ["<IfModule"],
     "match_status": [200],
     "success_words": ["<IfModule", "RewriteEngine", "Options"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "htpasswd", "name": "Exposed .htpasswd", "severity": "critical",
     "category": "exposed_config", "method": "GET", "path": "/.htpasswd",
     "match_regex": r"^[\w\-]+:\$",
     "success_words": ["$apr1$", "$2y$", "$2a$", ":{SHA}"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "wp-config-bak", "name": "Exposed wp-config.php backup",
     "severity": "critical", "category": "exposed_config", "method": "GET",
     "path": "/wp-config.php.bak",
     "match_words": ["DB_PASSWORD"],
     "success_words": ["DB_PASSWORD", "DB_NAME", "AUTH_KEY"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "config-php-bak", "name": "Exposed config.php backup",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/config.php.bak",
     "match_regex": r"(?:DB_|mysql_|mysqli_|PDO)",
     "success_words": ["DB_", "mysqli_", "PDO", "mysql_connect"],
     "fail_words": ["<html", "<!doctype"]},

    {"id": "web-config-bak", "name": "Exposed web.config backup",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/web.config.bak",
     "match_words": ["<configuration>"],
     "success_words": ["<configuration>", "<system.web>"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "appsettings", "name": "Exposed appsettings.json",
     "severity": "critical", "category": "exposed_config", "method": "GET",
     "path": "/appsettings.json",
     "match_regex": r'"(?:ConnectionStrings|Logging|AllowedHosts)"',
     "success_words": ["ConnectionStrings", "Logging", "AllowedHosts"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "appsettings-dev", "name": "Exposed appsettings.Development.json",
     "severity": "critical", "category": "exposed_config", "method": "GET",
     "path": "/appsettings.Development.json",
     "match_regex": r'"(?:ConnectionStrings|Logging)"',
     "success_words": ["ConnectionStrings", "Logging"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "application-properties", "name": "Exposed application.properties",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/application.properties",
     "match_regex": r"spring\.|server\.|datasource",
     "success_words": ["spring.", "server.", "datasource"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "application-yml", "name": "Exposed application.yml",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/application.yml",
     "match_regex": r"spring:|server:|datasource",
     "success_words": ["spring:", "server:", "datasource"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "composer-json", "name": "Exposed composer.json",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/composer.json",
     "match_words": ['"require"'],
     "success_words": ["require", "autoload", "name"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "composer-lock", "name": "Exposed composer.lock",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/composer.lock",
     "match_words": ['"packages"'],
     "success_words": ["packages", "content-hash", "plugin-api-version"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype"]},

    {"id": "package-json", "name": "Exposed package.json",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/package.json",
     "match_words": ['"dependencies"', '"version"'],
     "success_words": ["dependencies", "name", "version"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "package-lock", "name": "Exposed package-lock.json",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/package-lock.json",
     "match_words": ['"lockfileVersion"'],
     "success_words": ["lockfileVersion", "packages", "dependencies"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype"]},

    {"id": "yarn-lock", "name": "Exposed yarn.lock",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/yarn.lock",
     "match_words": ["# THIS IS AN AUTOGENERATED FILE"],
     "success_words": ["# THIS IS AN AUTOGENERATED FILE", "# yarn lockfile"],
     "fail_words": ["<html", "<!doctype"]},

    {"id": "dockerfile", "name": "Exposed Dockerfile",
     "severity": "medium", "category": "exposed_config", "method": "GET",
     "path": "/Dockerfile",
     "match_regex": r"^FROM\s",
     "success_words": ["FROM ", "RUN ", "COPY "],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "docker-compose", "name": "Exposed docker-compose.yml",
     "severity": "high", "category": "exposed_config", "method": "GET",
     "path": "/docker-compose.yml",
     "match_regex": r"services:\s*$|^\s+image:",
     "success_words": ["services:", "image:", "version:"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "makefile", "name": "Exposed Makefile",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/Makefile",
     "match_regex": r"^[\w\-]+\s*:",
     "success_words": ["all:", "build:", "install:", ".PHONY"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "requirements-txt", "name": "Exposed requirements.txt",
     "severity": "low", "category": "exposed_config", "method": "GET",
     "path": "/requirements.txt",
     "match_regex": r"^[\w\-]+\s*(?:==|>=|~=|<=)",
     "success_words": ["==", ">=", "~="],
     "fail_words": ["<html", "<!doctype", "<error"]},

    # ─── exposed secret material ──────────────────────────────────
    {"id": "id-rsa", "name": "Exposed SSH private key",
     "severity": "critical", "category": "exposed_secret", "method": "GET",
     "path": "/id_rsa",
     "match_words": ["-----BEGIN"],
     "success_words": ["-----BEGIN RSA PRIVATE KEY-----",
                       "-----BEGIN OPENSSH PRIVATE KEY-----",
                       "-----BEGIN PRIVATE KEY-----"],
     "match_status": [200],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "id-rsa-ssh-dir", "name": "Exposed .ssh/id_rsa",
     "severity": "critical", "category": "exposed_secret", "method": "GET",
     "path": "/.ssh/id_rsa",
     "match_words": ["PRIVATE KEY"],
     "success_words": ["PRIVATE KEY"],
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "id-ed25519", "name": "Exposed SSH ed25519 key",
     "severity": "critical", "category": "exposed_secret", "method": "GET",
     "path": "/id_ed25519",
     "match_words": ["PRIVATE KEY"],
     "success_words": ["BEGIN OPENSSH PRIVATE KEY"],
     "fail_words": ["<html", "<!doctype"]},

    # ─── swagger / openapi ────────────────────────────────────────
    {"id": "swagger-json", "name": "Exposed Swagger JSON",
     "severity": "medium", "category": "exposed_api_doc", "method": "GET",
     "path": "/swagger.json",
     "match_regex": r'"(?:swagger|openapi)"\s*:\s*"',
     "success_words": ["swagger", "openapi", "paths"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "openapi-json", "name": "Exposed OpenAPI JSON",
     "severity": "medium", "category": "exposed_api_doc", "method": "GET",
     "path": "/openapi.json",
     "match_regex": r'"openapi"\s*:\s*"',
     "success_words": ["openapi", "paths", "info"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "v2-api-docs", "name": "Exposed v2/api-docs",
     "severity": "medium", "category": "exposed_api_doc", "method": "GET",
     "path": "/v2/api-docs",
     "match_regex": r'"swagger"\s*:\s*"',
     "success_words": ["swagger", "paths"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "v3-api-docs", "name": "Exposed v3/api-docs",
     "severity": "medium", "category": "exposed_api_doc", "method": "GET",
     "path": "/v3/api-docs",
     "match_regex": r'"openapi"\s*:\s*"',
     "success_words": ["openapi", "paths"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "<error"]},

    {"id": "swagger-ui", "name": "Swagger UI exposed",
     "severity": "low", "category": "exposed_api_doc", "method": "GET",
     "path": "/swagger-ui.html",
     "match_words": ["Swagger UI"],
     "success_words": ["swagger-ui", "Swagger UI"],
     "fail_words": ["<html></html>", "404"]},

    {"id": "swagger-ui-idx", "name": "Swagger UI index exposed",
     "severity": "low", "category": "exposed_api_doc", "method": "GET",
     "path": "/swagger-ui/index.html",
     "match_words": ["Swagger"],
     "success_words": ["swagger-ui", "SwaggerUI"],
     "fail_words": ["404", "not found"]},

    # ─── actuator ─────────────────────────────────────────────────
    {"id": "actuator", "name": "Spring Boot Actuator root",
     "severity": "medium", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator",
     "match_regex": r'"_links"|"self"',
     "success_words": ["_links", "self", "health"],
     "expect_content_type": "json",
     "fail_words": ["<html", "<!doctype", "Whitelabel Error Page"]},

    {"id": "actuator-env", "name": "Actuator /env exposed",
     "severity": "high", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator/env",
     "match_regex": r'"(?:propertySources|activeProfiles)"',
     "success_words": ["propertySources", "activeProfiles"],
     "expect_content_type": "json",
     "fail_words": ["<html", "Whitelabel Error Page"]},

    {"id": "actuator-heapdump", "name": "Actuator /heapdump exposed",
     "severity": "critical", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator/heapdump",
     "match_status": [200],
     "min_len": 20000,
     "success_words": ["JAVA PROFILE", "HPROF"],
     "fail_words": ["Whitelabel", "404", "not found", "<html"]},

    {"id": "actuator-mappings", "name": "Actuator /mappings exposed",
     "severity": "medium", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator/mappings",
     "match_regex": r'"(?:mappings|dispatcherServlets)"',
     "success_words": ["mappings", "dispatcherServlets"],
     "expect_content_type": "json",
     "fail_words": ["<html", "Whitelabel"]},

    {"id": "actuator-beans", "name": "Actuator /beans exposed",
     "severity": "medium", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator/beans",
     "match_regex": r'"(?:beans|context)"',
     "success_words": ["beans", "context"],
     "expect_content_type": "json",
     "fail_words": ["<html", "Whitelabel"]},

    {"id": "actuator-threaddump", "name": "Actuator /threaddump exposed",
     "severity": "medium", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator/threaddump",
     "match_regex": r'"(?:threads|threadName)"',
     "success_words": ["threads", "threadName"],
     "expect_content_type": "json",
     "fail_words": ["<html", "Whitelabel"]},

    {"id": "actuator-httptrace", "name": "Actuator /httptrace exposed",
     "severity": "medium", "category": "exposed_actuator", "method": "GET",
     "path": "/actuator/httptrace",
     "match_regex": r'"(?:traces|request|response)"',
     "success_words": ["traces", "request", "response"],
     "expect_content_type": "json",
     "fail_words": ["<html", "Whitelabel"]},

    # ─── debug / admin ────────────────────────────────────────────
    {"id": "phpinfo", "name": "phpinfo() exposed", "severity": "medium",
     "category": "exposed_debug", "method": "GET", "path": "/phpinfo.php",
     "match_words": ["PHP Version", "php.ini"],
     "success_words": ["PHP Version", "php.ini", "PHP License"],
     "fail_words": ["<html></html>", "404", "not found"]},

    {"id": "server-status", "name": "Apache server-status exposed",
     "severity": "medium", "category": "exposed_debug", "method": "GET",
     "path": "/server-status",
     "match_words": ["Apache Server Status"],
     "success_words": ["Apache Server Status", "Total accesses"],
     "fail_words": ["<html></html>", "404", "not found"]},

    {"id": "server-info", "name": "Apache server-info exposed",
     "severity": "medium", "category": "exposed_debug", "method": "GET",
     "path": "/server-info",
     "match_words": ["Apache Server Information"],
     "success_words": ["Apache Server Information", "Server Settings"],
     "fail_words": ["<html></html>", "404"]},

    {"id": "nginx-status", "name": "nginx stub_status exposed",
     "severity": "medium", "category": "exposed_debug", "method": "GET",
     "path": "/nginx_status",
     "match_words": ["Active connections"],
     "success_words": ["Active connections", "server accepts handled requests"],
     "fail_words": ["<html", "404"]},

    {"id": "debug-vars", "name": "Go debug/vars exposed",
     "severity": "medium", "category": "exposed_debug", "method": "GET",
     "path": "/debug/vars",
     "match_regex": r'"(?:cmdline|memstats)"',
     "success_words": ["cmdline", "memstats"],
     "expect_content_type": "json",
     "fail_words": ["<html"]},

    {"id": "debug-pprof", "name": "Go debug/pprof exposed",
     "severity": "medium", "category": "exposed_debug", "method": "GET",
     "path": "/debug/pprof/",
     "match_words": ["Types of profiles available", "goroutine"],
     "success_words": ["Types of profiles available", "goroutine"],
     "fail_words": ["<html", "404"]},

    # ─── database interfaces ─────────────────────────────────────
    {"id": "phpmyadmin", "name": "phpMyAdmin interface",
     "severity": "medium", "category": "exposed_database", "method": "GET",
     "path": "/phpmyadmin/",
     "match_words": ["phpMyAdmin"],
     "success_words": ["phpMyAdmin", "pma_username", "pma_password"],
     "fail_words": ["404", "not found", "phpMyAdmin error"]},

    {"id": "adminer", "name": "Adminer interface", "severity": "high",
     "category": "exposed_database", "method": "GET", "path": "/adminer.php",
     "match_words": ["Adminer"],
     "success_words": ["Adminer", "loginForm", "username"],
     "fail_words": ["404", "not found"]},

    {"id": "mongo-express", "name": "Mongo-Express interface",
     "severity": "critical", "category": "exposed_database", "method": "GET",
     "path": "/mongo-express/",
     "match_words": ["Mongo Express"],
     "success_words": ["Mongo Express", "mongo-express", "database"],
     "fail_words": ["404", "not found"]},

    {"id": "redis-commander", "name": "Redis Commander interface",
     "severity": "critical", "category": "exposed_database", "method": "GET",
     "path": "/redis-commander/",
     "match_words": ["Redis Commander"],
     "success_words": ["Redis Commander", "redis-commander"],
     "fail_words": ["404", "not found"]},

    {"id": "elasticsearch", "name": "Elasticsearch HTTP interface",
     "severity": "critical", "category": "exposed_database", "method": "GET",
     "path": "/",
     "match_regex": r'"cluster_name".*"tagline".*"You Know, for Search"',
     "success_words": ["cluster_name", "tagline", "You Know, for Search"],
     "expect_content_type": "json",
     "fail_words": ["<html"]},

    {"id": "es-cat-indices", "name": "Elasticsearch indices enumerable",
     "severity": "critical", "category": "exposed_database", "method": "GET",
     "path": "/_cat/indices",
     "match_regex": r"^\w+\s+\w+\s+\d+",
     "match_status": [200],
     "success_words": ["open", "green", "yellow"],
     "fail_words": ["<html", "404"]},

    {"id": "couchdb", "name": "CouchDB welcome", "severity": "high",
     "category": "exposed_database", "method": "GET", "path": "/",
     "match_regex": r'"couchdb"\s*:\s*"Welcome"',
     "success_words": ["couchdb", "Welcome"],
     "expect_content_type": "json",
     "fail_words": ["<html"]},

    {"id": "couchdb-all-dbs", "name": "CouchDB databases enumerable",
     "severity": "critical", "category": "exposed_database", "method": "GET",
     "path": "/_all_dbs",
     "match_status": [200], "match_regex": r'^\[' or r"^\[",
     "success_words": ["_users", "_replicator", "_global_changes"],
     "expect_content_type": "json",
     "fail_words": ["<html", "404"]},

    {"id": "couchdb-utils", "name": "CouchDB Fauxton UI exposed",
     "severity": "medium", "category": "exposed_database", "method": "GET",
     "path": "/_utils/",
     "match_words": ["Fauxton"],
     "success_words": ["Fauxton", "couchdb"],
     "fail_words": ["404", "not found"]},

    {"id": "prometheus-graph", "name": "Prometheus UI exposed",
     "severity": "medium", "category": "exposed_database", "method": "GET",
     "path": "/graph",
     "match_words": ["Prometheus", "Graph"],
     "success_words": ["Prometheus", "Graph", "prometheus"],
     "fail_words": ["404", "not found"]},

    {"id": "prometheus-api", "name": "Prometheus API exposed",
     "severity": "medium", "category": "exposed_database", "method": "GET",
     "path": "/api/v1/targets",
     "match_regex": r'"status"\s*:\s*"success"',
     "success_words": ["status", "success", "data"],
     "expect_content_type": "json",
     "fail_words": ["<html", "404"]},

    {"id": "influxdb-query", "name": "InfluxDB query endpoint",
     "severity": "high", "category": "exposed_database", "method": "GET",
     "path": "/query?q=SHOW+DATABASES",
     "match_regex": r'"results"',
     "success_words": ["results", "series", "statement_id"],
     "expect_content_type": "json",
     "fail_words": ["<html", "404"]},

    {"id": "kibana", "name": "Kibana UI exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/app/kibana",
     "match_words": ["kibana", "Kibana"],
     "success_words": ["kibana", "Kibana"],
     "fail_words": ["404", "not found", "Site not configured"]},

    {"id": "grafana", "name": "Grafana UI exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/login",
     "match_words": ["grafanaBootData", "Grafana"],
     "success_words": ["grafanaBootData", "Grafana", "grafana"],
     "fail_words": ["404", "not found"]},

    {"id": "solr", "name": "Solr admin exposed", "severity": "medium",
     "category": "exposed_database", "method": "GET", "path": "/solr/",
     "match_words": ["Solr Admin", "solr"],
     "success_words": ["Solr Admin", "solr", "lucene"],
     "fail_words": ["404", "not found"]},

    {"id": "arangodb", "name": "ArangoDB web UI exposed",
     "severity": "high", "category": "exposed_database", "method": "GET",
     "path": "/_db/_system/_admin/aardvark/index.html",
     "match_words": ["ArangoDB", "aardvark"],
     "success_words": ["ArangoDB", "aardvark"],
     "fail_words": ["404", "not found"]},

    {"id": "neo4j-browser", "name": "Neo4j browser exposed",
     "severity": "medium", "category": "exposed_database", "method": "GET",
     "path": "/browser/",
     "match_words": ["Neo4j", "browser"],
     "success_words": ["Neo4j", "browser"],
     "fail_words": ["404", "not found"]},

    {"id": "clickhouse-http", "name": "ClickHouse HTTP reachable",
     "severity": "high", "category": "exposed_database", "method": "GET",
     "path": "/?query=SELECT%20version()",
     "match_status": [200],
     "success_words": ["ClickHouse", "version"],
     "fail_words": ["<html", "not found", "404"]},

    # ─── bucket ──────────────────────────────────────────────────
    {"id": "s3-listable", "name": "S3 bucket listable", "severity": "high",
     "category": "exposed_bucket", "method": "GET",
     "path": "/?list-type=2",
     "match_words": ["<ListBucketResult"],
     "success_words": ["ListBucketResult", "KeyCount", "<Key>"],
     "fail_words": ["<Error>", "NoSuchBucket", "AccessDenied"]},

    # ─── ci / devops ─────────────────────────────────────────────
    {"id": "jenkins", "name": "Jenkins dashboard exposed",
     "severity": "medium", "category": "exposed_admin", "method": "GET",
     "path": "/",
     "match_words": ["Jenkins", "Dashboard"],
     "success_words": ["Jenkins", "Dashboard", "jenkins"],
     "fail_words": ["404", "not found"]},

    {"id": "jenkins-script", "name": "Jenkins script console exposed",
     "severity": "critical", "category": "exposed_admin", "method": "GET",
     "path": "/script",
     "match_words": ["Groovy script", "Script Console"],
     "success_words": ["Groovy script", "Script Console", "Groovy"],
     "fail_words": ["404", "not found", "Please login"]},

    {"id": "gitlab", "name": "GitLab login exposed", "severity": "low",
     "category": "exposed_admin", "method": "GET", "path": "/users/sign_in",
     "match_words": ["GitLab", "sign in"],
     "success_words": ["GitLab", "sign_in", "gitlab"],
     "fail_words": ["404", "not found"]},

    {"id": "grafana-login", "name": "Grafana login exposed",
     "severity": "low", "category": "exposed_admin", "method": "GET",
     "path": "/login",
     "match_words": ["grafana", "login"],
     "success_words": ["grafanaBootData", "Grafana", "grafana"],
     "fail_words": ["404", "not found"]},

    {"id": "kibana-login", "name": "Kibana login exposed",
     "severity": "low", "category": "exposed_admin", "method": "GET",
     "path": "/login",
     "match_words": ["Kibana", "login"],
     "success_words": ["kbn-injected-metadata", "Kibana"],
     "fail_words": ["404", "not found"]},

    # ─── web shell / backdoor ────────────────────────────────────
    {"id": "webshell-c99", "name": "Possible c99 web shell",
     "severity": "critical", "category": "webshell", "method": "GET",
     "path": "/c99.php",
     "match_words": ["c99shell", "c99madShell"],
     "success_words": ["c99shell", "c99madShell", "c99.php"],
     "fail_words": ["404", "not found"]},

    {"id": "webshell-r57", "name": "Possible r57 web shell",
     "severity": "critical", "category": "webshell", "method": "GET",
     "path": "/r57.php",
     "match_words": ["r57shell", "r57"],
     "success_words": ["r57shell", "r57"],
     "fail_words": ["404", "not found"]},

    {"id": "webshell-wso", "name": "Possible WSO web shell",
     "severity": "critical", "category": "webshell", "method": "GET",
     "path": "/wso.php",
     "match_words": ["wsoEx", "WSO 2."],
     "success_words": ["wsoEx", "WSO 2."],
     "fail_words": ["404", "not found"]},

    # ─── specific CVE fingerprint hints ──────────────────────────
    {"id": "wp-json-users", "name": "WordPress REST user enumeration",
     "severity": "medium", "category": "wordpress", "method": "GET",
     "path": "/wp-json/wp/v2/users",
     "match_regex": r'"(?:id|slug|name)"\s*:',
     "success_words": ["slug", "name", "id"],
     "expect_content_type": "json",
     "fail_words": ["<html", "rest_no_route", "rest_forbidden", "rest_cannot_access"]},

    {"id": "wp-xmlrpc", "name": "WordPress xmlrpc.php enabled",
     "severity": "low", "category": "wordpress", "method": "GET",
     "path": "/xmlrpc.php",
     "match_words": ["XML-RPC server accepts POST requests only"],
     "success_words": ["XML-RPC server accepts POST requests only"],
     "fail_words": ["404", "not found"]},

    {"id": "wp-readme", "name": "WordPress readme.html leaks version",
     "severity": "low", "category": "wordpress", "method": "GET",
     "path": "/readme.html",
     "match_words": ["WordPress"],
     "success_words": ["WordPress", "Semantic Personal Publishing"],
     "fail_words": ["404", "not found"]},

    {"id": "drupal-changelog", "name": "Drupal CHANGELOG.txt exposed",
     "severity": "low", "category": "drupal", "method": "GET",
     "path": "/CHANGELOG.txt",
     "match_words": ["Drupal "],
     "success_words": ["Drupal ", "Drupal 7", "Drupal 8", "Drupal 9", "Drupal 10"],
     "fail_words": ["404", "not found"]},

    {"id": "joomla-manifest", "name": "Joomla manifest exposes version",
     "severity": "low", "category": "joomla", "method": "GET",
     "path": "/administrator/manifests/files/joomla.xml",
     "match_words": ["<version>"],
     "success_words": ["joomla", "Joomla", "<version>"],
     "fail_words": ["404", "not found"]},

    {"id": "laravel-debug", "name": "Laravel debug mode (IGNITION/Whoops)",
     "severity": "high", "category": "framework", "method": "GET",
     "path": "/_ignition/health-check",
     "match_status": [200], "match_words": ["can_execute_commands"],
     "success_words": ["can_execute_commands"],
     "expect_content_type": "json",
     "fail_words": ["<html", "404"]},

    {"id": "rails-debug", "name": "Rails exception page exposed",
     "severity": "medium", "category": "framework", "method": "GET",
     "path": "/rails/info/properties",
     "match_words": ["Rails version"],
     "success_words": ["Rails version", "Rails::Info"],
     "fail_words": ["404", "not found"]},

    {"id": "spring-boot-error", "name": "Spring Boot error page leaks",
     "severity": "low", "category": "framework", "method": "GET",
     "path": "/error",
     "match_words": ["Whitelabel Error Page"],
     "success_words": ["Whitelabel Error Page", "There was an unexpected error"],
     "fail_words": ["404", "not found"]},
]


# ═══════════════════════════════════════════════════════════════════
# MATCHER
# ═══════════════════════════════════════════════════════════════════
_CT_MAP = {
    "json": ("json",),
    "html": ("html", "xhtml"),
    "text": ("text",),
    "xml": ("xml",),
    "octet": ("octet-stream", "binary"),
}


def _content_type_ok(expected: str, content_type: str) -> bool:
    if not expected:
        return True
    ct = (content_type or "").lower()
    if not ct:
        return True  # unknown — allow (many small endpoints omit it)
    tokens = _CT_MAP.get(expected, (expected,))
    return any(t in ct for t in tokens)


def _has_any(body_l: str, words: list[str]) -> Optional[str]:
    for w in words:
        if w and w.lower() in body_l:
            return w
    return None


def _match_template(tpl: dict, status: int, headers: dict, body: str) -> tuple[bool, str]:
    """
    Returns (matched, evidence). Disciplined:
      1. status must be in match_status (default [200])
      2. global fail words + per-template fail_words must NOT appear
      3. content-type must match expect_content_type (if set)
      4. min_len / max_len enforced
      5. all match_words must appear
      6. match_any_words — at least one must appear
      7. success_words — at least one must appear
      8. match_regex must match
    """
    body_l = (body or "").lower()
    ct = headers.get("content-type", "")

    # 1. status
    match_status = tpl.get("match_status") or [200]
    if status not in match_status:
        return False, ""

    # 4. length guards
    blen = len(body or "")
    if "min_len" in tpl and blen < tpl["min_len"]:
        return False, ""
    if "max_len" in tpl and blen > tpl["max_len"]:
        return False, ""

    # 2. hard negatives — global default + per-template
    fail_list = list(DEFAULT_FAIL_WORDS) + list(tpl.get("fail_words") or [])
    # legacy alias
    fail_list += list(tpl.get("not_words") or [])
    hit_fail = _has_any(body_l, fail_list)
    if hit_fail:
        return False, ""

    # 3. content-type
    if not _content_type_ok(tpl.get("expect_content_type", ""), ct):
        return False, ""

    # 5. all match_words
    evidence_parts = []
    for w in tpl.get("match_words") or []:
        if w.lower() not in body_l:
            return False, ""
        evidence_parts.append(f"word:{w!r}")

    # 6. match_any_words
    any_words = tpl.get("match_any_words") or []
    if any_words:
        got = _has_any(body_l, any_words)
        if not got:
            return False, ""
        evidence_parts.append(f"any:{got!r}")

    # 7. success_words — soft confirmation
    sw = tpl.get("success_words") or []
    if sw:
        got = _has_any(body_l, sw)
        if not got:
            return False, ""
        evidence_parts.append(f"success:{got!r}")

    # 8. regex
    if rx := tpl.get("match_regex"):
        m = re.search(rx, body or "", re.I | re.M)
        if not m:
            return False, ""
        evidence_parts.append(f"regex:{m.group(0)[:120]}")

    if not evidence_parts:
        # no positive signal at all — require at least one, else we're guessing
        # from status alone. To be safe, reject.
        return False, ""

    return True, " | ".join(evidence_parts)


# ═══════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════
async def _run_template(client: HttpClient, base_url: str, tpl: dict) -> Optional[Finding]:
    path = tpl["path"]
    paths = path if isinstance(path, list) else [path]
    method = (tpl.get("method") or "GET").upper()

    for p in paths:
        url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
        if method == "POST":
            r = await client.post(url, content=tpl.get("body") or b"",
                                  headers=tpl.get("headers") or {})
        else:
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
                extra={"template_id": tpl["id"], "status": r.status_code,
                       "content_type": headers.get("content-type", "")},
                remediation=tpl.get("remediation", ""),
            )
    return None


async def run(client: HttpClient, base_url: str,
              extra_templates: list[dict] | None = None) -> list[Finding]:
    """Run all templates. Returns findings."""
    templates = list(TEMPLATES)
    if extra_templates:
        templates.extend(extra_templates)

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
