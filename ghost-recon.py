#!/usr/bin/env python3
"""
Ghost-Recon v1.0.0 - Framework de Reconhecimento Ofensivo
==========================================================
Ferramenta profissional de reconhecimento para pentest e pesquisa de seguranca.
Realiza enumeracao completa de um dominio/alvo incluindo DNS, SSL/TLS, HTTP
fingerprinting, deteccao de WAF/CDN, tecnologias, auditoria de headers de
seguranca, varredura de portas, brute-force de subdomains, verificacao de
seguranca de email (SPF/DKIM/DMARC) e consulta a Certificate Transparency logs.

Modulos:
  --dns            Enumeracao completa de registros DNS (A/AAAA/MX/NS/TXT/SOA/CAA)
  --whois          Informacoes WHOIS do dominio
  --ssl            Analise de certificado SSL/TLS (validade, emitente, SANs)
  --http           Fingerprinting HTTP (headers, servidor, redirecionamentos)
  --waf            Deteccao de WAF/CDN (Cloudflare, AWS, Akamai, Imperva, etc.)
  --tech           Identificacao de tecnologias (CMS, frameworks, linguagens)
  --headers        Auditoria de headers de seguranca (HSTS, CSP, X-Frame, etc.)
  --portas         Varredura de portas TCP com banner grabbing
  --subdomains     Brute-force de subdomains com wordlist embutida ou customizada
  --email          Verificacao de seguranca de email (SPF, DKIM, DMARC, MTA-STS)
  --ct             Certificate Transparency logs via crt.sh
  --completo       Executa todos os modulos acima

Exemplos:
  python ghost-recon.py -d exemplo.com
  python ghost-recon.py -d exemplo.com --completo
  python ghost-recon.py -d exemplo.com --dns --ssl --http --headers
  python ghost-recon.py -d exemplo.com --subdomains --threads 30
  python ghost-recon.py -d exemplo.com --subdomains --wordlist minha-lista.txt
  python ghost-recon.py -d exemplo.com --portas --portas-lista "80,443,8080,8443,3306"
  python ghost-recon.py -d exemplo.com --portas --portas-top50
  python ghost-recon.py -d exemplo.com --waf --tech --headers
  python ghost-recon.py -d exemplo.com --email
  python ghost-recon.py -d exemplo.com --ct --ct-limite 200
  python ghost-recon.py -d exemplo.com --completo --output resultado.json
  python ghost-recon.py -d exemplo.com --stealth --rate-limit 5 --proxy http://127.0.0.1:8080
  python ghost-recon.py -d exemplo.com --timeout 5 --verbose

Dependencias:
  pip install requests
  pip install dnspython  (opcional - melhora resolucao DNS)

Autor: By Gh0st-Bx1 | github.com/Ghost-Bx1
"""

import argparse
import concurrent.futures
import json
import random
import re
import socket
import ssl as ssl_lib
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from threading import Lock

try:
    import requests
    from requests.adapters import HTTPAdapter
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    import dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False

VERSAO = "2.0.0"

BANNER = r"""
   _____ _               _     ____
  / ____| |             | |   |  _ \
 | |  __| |__   ___  ___| |_  | |_) | ___  ___ ___  _ __
 | | |_ | '_ \ / _ \/ __| __| |  _ < / _ \/ __/ _ \| '_ \
 | |__| | | | | (_) \__ \ |_  | |_) |  __/ (_| (_) | | | |
  \_____|_| |_|\___/|___/\__| |____/ \___|\___\___/|_| |_|

  Ghost-Recon v{v}  |  Framework de Reconhecimento Ofensivo
  By Gh0st-Bx1  |  github.com/Ghost-Bx1
""".format(v=VERSAO)

C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m",
    "B": "\033[94m", "M": "\033[95m", "C": "\033[96m",
    "W": "\033[97m", "X": "\033[0m",  "N": "\033[1m", "D": "\033[2m",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "curl/8.5.0",
]

WAF_ASSINATURAS = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "cf-mitigated"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "server": ["cloudflare"],
        "body": ["Attention Required! | Cloudflare", "Ray ID:", "cloudflare.com/5xx-error-landing",
                 "DDoS protection by Cloudflare"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid", "x-amz-id-2",
                    "x-amzn-trace-id"],
        "cookies": [],
        "server": ["AmazonS3", "CloudFront"],
        "body": ["Request blocked", "AWS WAF", "403 ERROR"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-check-cacheable", "x-akamai-request-id",
                    "akamai-origin-hop", "x-akamai-edgescape"],
        "cookies": ["ak_bmsc", "bm_sz", "bm_sv"],
        "server": ["AkamaiGHost", "Akamai"],
        "body": ["Access Denied", "Reference #", "akamai.net"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "x-wa-info", "x-f5-request-id"],
        "cookies": ["TS01", "TS0"],
        "server": ["BigIP", "BIG-IP", "F5 BIG-IP"],
        "body": ["The requested URL was rejected", "F5 Networks"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["visid_incap_", "incap_ses_", "nlbi_"],
        "server": ["Imperva"],
        "body": ["Incapsula incident ID", "_Incapsula_Resource", "Imperva"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": [],
        "server": ["Sucuri/Cloudproxy"],
        "body": ["Access Denied - Sucuri Website Firewall", "sucuri.net"],
    },
    "Barracuda": {
        "headers": ["x-barracuda-connect"],
        "cookies": ["barra_counter_session"],
        "server": ["Barracuda"],
        "body": ["You are not authorized to view this page", "Barracuda Web Application Firewall"],
    },
    "Fastly / Varnish": {
        "headers": ["x-served-by", "x-cache-hits", "x-timer", "fastly-restarts", "x-fastly-request-id"],
        "cookies": [],
        "server": ["Varnish", "varnish"],
        "body": [],
    },
    "ModSecurity": {
        "headers": ["x-mod-security-message"],
        "cookies": [],
        "server": [],
        "body": ["ModSecurity", "This error was generated by Mod_Security", "Mod_Security"],
    },
    "Reblaze": {
        "headers": ["x-rb-timer"],
        "cookies": ["rbzid"],
        "server": [],
        "body": [],
    },
    "Radware AppWall": {
        "headers": ["x-sl-compstate"],
        "cookies": ["AIDPS"],
        "server": ["Protected by Radware"],
        "body": ["Unauthorized Activity Has Been Detected", "Radware"],
    },
    "Wordfence": {
        "headers": [],
        "cookies": ["wfvt_"],
        "server": [],
        "body": ["Generated by Wordfence", "wordfence.com", "Wordfence"],
    },
    "StackPath": {
        "headers": ["x-sp-id"],
        "cookies": [],
        "server": ["StackPath"],
        "body": ["Blocked | StackPath"],
    },
    "Edgecast / Verizon": {
        "headers": ["x-ec-custom-error", "x-pull-zone-id"],
        "cookies": [],
        "server": ["ECS"],
        "body": [],
    },
}

TECH_ASSINATURAS = {
    "WordPress": {
        "headers_match": {},
        "cookies": ["wordpress_", "wp-settings-", "wp_"],
        "body": ["wp-content/", "wp-includes/", "xmlrpc.php"],
        "meta": ["WordPress"],
    },
    "Drupal": {
        "headers_match": {"x-drupal-cache": ".*"},
        "cookies": ["DRUPAL_UID", "Drupal"],
        "body": ["/sites/default/files/", "Drupal.settings"],
        "meta": ["Drupal"],
    },
    "Joomla": {
        "headers_match": {},
        "cookies": [],
        "body": ["/components/com_", "/templates/"],
        "meta": ["Joomla"],
    },
    "Magento": {
        "headers_match": {},
        "cookies": ["frontend", "MAGE_CACHE_SESSID"],
        "body": ["Mage.Cookies", "/skin/frontend/", "mage/"],
        "meta": [],
    },
    "Shopify": {
        "headers_match": {},
        "cookies": ["_shopify_"],
        "body": ["Shopify.theme", "cdn.shopify.com"],
        "meta": [],
    },
    "WooCommerce": {
        "headers_match": {},
        "cookies": ["woocommerce_"],
        "body": ["woocommerce", "WooCommerce"],
        "meta": [],
    },
    "Django": {
        "headers_match": {},
        "cookies": ["csrftoken", "sessionid"],
        "body": ["csrfmiddlewaretoken"],
        "meta": [],
    },
    "Laravel / PHP": {
        "headers_match": {"x-powered-by": "PHP"},
        "cookies": ["laravel_session", "XSRF-TOKEN", "PHPSESSID"],
        "body": [],
        "meta": [],
    },
    "ASP.NET": {
        "headers_match": {"x-aspnet-version": ".*", "x-aspnetmvc-version": ".*"},
        "cookies": ["ASP.NET_SessionId", "__RequestVerificationToken"],
        "body": ["__VIEWSTATE", "__EVENTVALIDATION", "WebResource.axd"],
        "meta": [],
    },
    "Next.js": {
        "headers_match": {"x-powered-by": "Next\\.js"},
        "cookies": [],
        "body": ["__NEXT_DATA__", "_next/static/", "/_next/"],
        "meta": [],
    },
    "Nuxt.js": {
        "headers_match": {},
        "cookies": [],
        "body": ["_nuxt/", "__NUXT__"],
        "meta": [],
    },
    "React": {
        "headers_match": {},
        "cookies": [],
        "body": ["data-reactroot", "react.production.min.js", "__reactFiber"],
        "meta": [],
    },
    "Vue.js": {
        "headers_match": {},
        "cookies": [],
        "body": ["vue.min.js", "__vue__", "data-v-"],
        "meta": [],
    },
    "Angular": {
        "headers_match": {},
        "cookies": [],
        "body": ["ng-version=", "angular.min.js", "ng-app"],
        "meta": [],
    },
    "Ruby on Rails": {
        "headers_match": {"x-powered-by": "Phusion Passenger"},
        "cookies": ["_session_id"],
        "body": ["data-turbolinks-", "rails-ujs"],
        "meta": [],
    },
    "Express.js / Node.js": {
        "headers_match": {"x-powered-by": "Express"},
        "cookies": ["connect.sid"],
        "body": [],
        "meta": [],
    },
    "Apache": {
        "headers_match": {"server": "Apache"},
        "cookies": [],
        "body": [],
        "meta": [],
    },
    "Nginx": {
        "headers_match": {"server": "nginx"},
        "cookies": [],
        "body": [],
        "meta": [],
    },
    "Microsoft IIS": {
        "headers_match": {"server": "Microsoft-IIS"},
        "cookies": [],
        "body": [],
        "meta": [],
    },
    "Tomcat": {
        "headers_match": {"server": "Apache-Coyote"},
        "cookies": ["JSESSIONID"],
        "body": ["Apache Tomcat"],
        "meta": [],
    },
    "Spring Boot": {
        "headers_match": {},
        "cookies": ["JSESSIONID", "SESSION"],
        "body": ["Spring Boot", "Whitelabel Error Page"],
        "meta": [],
    },
    "Grafana": {
        "headers_match": {},
        "cookies": ["grafana_session"],
        "body": ["Grafana", "grafana-app"],
        "meta": [],
    },
    "Jenkins": {
        "headers_match": {"x-jenkins": ".*"},
        "cookies": ["JSESSIONID."],
        "body": ["Jenkins", "hudson"],
        "meta": [],
    },
    "Elasticsearch": {
        "headers_match": {},
        "cookies": [],
        "body": ["\"cluster_name\"", "\"version\" : {", "lucene_version"],
        "meta": [],
    },
}

HEADERS_SEGURANCA = {
    "Strict-Transport-Security": {
        "descricao": "HSTS - forca HTTPS",
        "critico": True,
        "regex_bom": r"max-age=\d+",
        "recomendado": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "descricao": "CSP - previne XSS e injecoes",
        "critico": True,
        "regex_bom": None,
        "recomendado": "default-src 'self'",
    },
    "X-Frame-Options": {
        "descricao": "Previne clickjacking",
        "critico": True,
        "regex_bom": r"(DENY|SAMEORIGIN)",
        "recomendado": "DENY",
    },
    "X-Content-Type-Options": {
        "descricao": "Previne MIME sniffing",
        "critico": False,
        "regex_bom": r"nosniff",
        "recomendado": "nosniff",
    },
    "Referrer-Policy": {
        "descricao": "Controla informacoes de referrer",
        "critico": False,
        "regex_bom": r"(no-referrer|strict-origin|same-origin)",
        "recomendado": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "descricao": "Controla APIs do browser",
        "critico": False,
        "regex_bom": None,
        "recomendado": "camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "descricao": "Header XSS legado (depreciado)",
        "critico": False,
        "regex_bom": r"1; mode=block",
        "recomendado": "1; mode=block",
    },
    "Cross-Origin-Opener-Policy": {
        "descricao": "Isolamento de processo cross-origin",
        "critico": False,
        "regex_bom": r"(same-origin|same-origin-allow-popups)",
        "recomendado": "same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "descricao": "Controla acesso a recursos cross-origin",
        "critico": False,
        "regex_bom": r"(same-site|same-origin)",
        "recomendado": "same-origin",
    },
}

PORTAS_COMUNS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 3000, 3306, 3389, 3690,
    4443, 4444, 4899, 5000, 5432, 5900, 5984, 6379, 6667, 7001,
    7070, 7443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 27018, 28017, 50000, 50070,
]

PORTA_SERVICO = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP/TLS", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle DB", 1723: "PPTP",
    2049: "NFS", 2082: "cPanel HTTP", 2083: "cPanel HTTPS",
    2086: "WHM HTTP", 2087: "WHM HTTPS", 3000: "Dev/Grafana",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "Metasploit",
    4899: "Radmin", 5000: "Flask/UPnP", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6667: "IRC",
    7001: "WebLogic", 7070: "RealServer", 8000: "HTTP Alt",
    8008: "HTTP Alt", 8080: "HTTP Proxy", 8081: "HTTP Alt",
    8443: "HTTPS Alt", 8888: "Jupyter/HTTP", 9000: "PHP-FPM",
    9090: "Cockpit/Alt", 9200: "Elasticsearch HTTP",
    9300: "Elasticsearch Transport", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 28017: "MongoDB Web",
    50000: "IBM DB2", 50070: "Hadoop HDFS",
}

SUBDOMAINS_LISTA = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "vpn", "m", "mobile", "shop", "store", "api", "dev", "staging",
    "test", "beta", "alpha", "blog", "forum", "support", "help",
    "portal", "admin", "panel", "dashboard", "login", "secure",
    "cdn", "static", "assets", "media", "img", "images", "video",
    "docs", "wiki", "kb", "status", "monitor", "grafana", "kibana",
    "jenkins", "jira", "git", "gitlab", "bitbucket", "svn",
    "chat", "irc", "mx", "mx1", "mx2", "mail2", "email", "smtp2",
    "pop3", "imap", "exchange", "owa", "autodiscover",
    "auth", "sso", "oauth", "id", "account", "accounts",
    "members", "user", "users", "profile", "register", "signup",
    "payment", "pay", "billing", "invoice", "checkout", "cart",
    "app", "apps", "web", "www2", "www3", "cloud", "storage",
    "backup", "archive", "files", "download", "upload",
    "proxy", "gateway", "lb", "loadbalancer",
    "internal", "intranet", "local", "corp", "office",
    "hr", "finance", "legal", "marketing", "sales", "crm",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "queue", "worker", "scheduler", "search", "es", "elastic",
    "analytics", "stats", "metrics", "logs",
    "graphql", "v1", "v2", "v3", "sandbox", "lab", "labs",
    "demo", "poc", "preview", "uat", "prod", "production",
    "new", "old", "legacy", "us", "eu", "uk", "br", "asia",
    "phpmyadmin", "pma", "adminer", "cpanel", "whm", "plesk",
    "api2", "api3", "api-v1", "api-v2",
    "health", "healthcheck", "alert", "alerts", "webhook",
    "report", "reports", "cms", "content", "extranet", "partner",
    "noc", "ops", "devops", "tools",
    "iot", "edge", "relay", "hub",
    "mx3", "mail3", "smtp3", "smtp4",
    "s3", "bucket", "blob",
    "waf", "firewall", "security",
    "api-gateway", "microservice", "k8s", "kubernetes",
    "docker", "registry", "artifactory", "nexus",
    "confluence", "trello", "notion",
    "vpn2", "remote", "rdp", "bastion", "jump",
    "wireless", "wifi", "hotspot",
    "ftp2", "sftp", "ftps",
    "webmail", "roundcube", "zimbra",
    "chat2", "im", "teams", "meet",
    "test2", "dev2", "staging2",
    "apm", "trace", "zipkin", "jaeger",
    "vault", "secrets",
    "www4", "www5",
    "whois", "rdap",
    "webdav", "caldav", "carddav",
    "api-docs", "swagger", "openapi",
    "mfa", "totp", "2fa",
    "idp", "saml", "ldap",
    "smtp-relay", "postmaster", "abuse",
    "autoconfig", "autoconfiguration",
]

_lock = Lock()


def _log(msg, nivel="INFO", verbose_only=False, verbose=False):
    if verbose_only and not verbose:
        return
    estilos = {
        "INFO":    (C["B"], "[*]"),
        "OK":      (C["G"], "[+]"),
        "ERRO":    (C["R"], "[-]"),
        "ALERTA":  (C["Y"], "[!]"),
        "TITULO":  (C["C"] + C["N"], "[=]"),
        "DEBUG":   (C["D"], "[D]"),
        "ACHADO":  (C["M"] + C["N"], "[>]"),
        "CRITICO": (C["R"] + C["N"], "[!!!]"),
    }
    cor, simbolo = estilos.get(nivel, (C["W"], "[*]"))
    with _lock:
        print(f"  {cor}{simbolo} {msg}{C['X']}")


def _secao(titulo):
    linha = "-" * 60
    with _lock:
        print(f"\n{C['C']}{C['N']}  {'=' * 60}")
        print(f"  {titulo}")
        print(f"  {'=' * 60}{C['X']}")


def _progresso(atual, total, prefixo=""):
    pct = int((atual / total) * 30) if total > 0 else 0
    barra = "[" + "#" * pct + "." * (30 - pct) + "]"
    with _lock:
        print(f"\r  {C['D']}{prefixo} {barra} {atual}/{total}{C['X']}", end="", flush=True)


def _finalizar_progresso():
    print()


def _get_ua(stealth=False):
    if stealth:
        return random.choice(USER_AGENTS)
    return USER_AGENTS[0]


def _rate_sleep(rate_limit):
    if rate_limit and rate_limit > 0:
        time.sleep(1.0 / rate_limit)


def _doh_query(dominio, tipo="A"):
    """DNS-over-HTTPS via Google como fallback quando dnspython nao esta instalado."""
    try:
        url = "https://dns.google/resolve?name={}&type={}".format(
            urllib.parse.quote(dominio), tipo
        )
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        if data.get("Status") == 0 and "Answer" in data:
            return [str(r.get("data", "")).rstrip(".") for r in data["Answer"]]
    except Exception:
        pass
    return []


def _resolver_dns(dominio, tipo="A", verbose=False):
    """Resolve registros DNS via dnspython (preferencial) ou Google DoH."""
    if DNS_OK:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            resp = resolver.resolve(dominio, tipo)
            return [str(r).rstrip(".") for r in resp]
        except dns.exception.NXDOMAIN:
            return []
        except Exception as e:
            _log(f"dnspython erro ({tipo}): {e}", "DEBUG", verbose_only=True, verbose=verbose)
    return _doh_query(dominio, tipo)


def _get_session(proxy=None, timeout=10):
    """Cria sessao requests configurada."""
    if not REQUESTS_OK:
        return None
    sess = requests.Session()
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    sess.verify = False
    sess.timeout = timeout
    return sess


# ==============================================================================
# MODULO: DNS
# ==============================================================================

def recon_dns(dominio, verbose=False):
    """Enumera registros DNS completos do dominio."""
    resultado = {
        "dominio": dominio,
        "registros": {},
        "ns_autoritativo": [],
        "resumo": [],
    }

    tipos = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
    for tipo in tipos:
        registros = _resolver_dns(dominio, tipo, verbose)
        if registros:
            resultado["registros"][tipo] = registros
            _log(f"  {tipo:6} -> {', '.join(registros[:3])}", "OK")
            if len(registros) > 3:
                _log(f"         + {len(registros) - 3} registros adicionais", "INFO")
        else:
            _log(f"  {tipo:6} -> (nenhum)", "DEBUG", verbose_only=True, verbose=verbose)

    # CNAME na raiz (incomum mas acontece)
    cname = _resolver_dns(dominio, "CNAME", verbose)
    if cname:
        resultado["registros"]["CNAME"] = cname
        _log(f"  {'CNAME':6} -> {', '.join(cname)}", "OK")

    # Verificar zone transfer (apenas indica, nao executa)
    ns_list = resultado["registros"].get("NS", [])
    if ns_list:
        resultado["ns_autoritativo"] = ns_list
        _log(f"  Servidores NS: {', '.join(ns_list)}", "INFO")
        # Verificar se NS permite transferencia de zona
        for ns in ns_list[:2]:
            try:
                ns_ip = socket.gethostbyname(ns)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                if sock.connect_ex((ns_ip, 53)) == 0:
                    resultado["resumo"].append(f"Porta 53/TCP aberta em {ns} ({ns_ip}) - possivel AXFR")
                sock.close()
            except Exception:
                pass

    # Verificar subdomain takeover via CNAME dangling
    cnames = resultado["registros"].get("CNAME", [])
    for cname_val in cnames:
        try:
            addrs = _resolver_dns(cname_val, "A", verbose)
            if not addrs:
                alerta = f"CNAME dangling: {dominio} -> {cname_val} (sem resolucao A) - possivel takeover!"
                _log(alerta, "CRITICO")
                resultado["resumo"].append(alerta)
        except Exception:
            pass

    return resultado


# ==============================================================================
# MODULO: WHOIS
# ==============================================================================

def recon_whois(dominio, verbose=False):
    """Obtem informacoes WHOIS via socket."""
    resultado = {"dominio": dominio, "raw": "", "campos": {}}

    servidores_whois = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io":  "whois.nic.io",
        "co":  "whois.nic.co",
        "br":  "whois.registro.br",
        "uk":  "whois.nic.uk",
        "de":  "whois.denic.de",
        "fr":  "whois.nic.fr",
        "it":  "whois.nic.it",
        "es":  "whois.nic.es",
        "ru":  "whois.tcinet.ru",
        "cn":  "whois.cnnic.cn",
        "jp":  "whois.jprs.jp",
        "au":  "whois.auda.org.au",
        "ca":  "whois.cira.ca",
        "nl":  "whois.domain-registry.nl",
        "be":  "whois.dns.be",
        "pl":  "whois.dns.pl",
        "eu":  "whois.eu",
    }

    tld = dominio.split(".")[-1].lower()
    servidor = servidores_whois.get(tld, "whois.iana.org")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((servidor, 43))
        sock.send((dominio + "\r\n").encode())
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
        texto = raw.decode("utf-8", errors="ignore")
        resultado["raw"] = texto[:3000]

        # Extrair campos relevantes
        campos = {
            "registrar": r"(?:Registrar|Registrar Name):\s*(.+)",
            "registrante": r"(?:Registrant Organization|Registrant Name):\s*(.+)",
            "criado": r"(?:Creation Date|Created|Registration Time):\s*(.+)",
            "expira": r"(?:Registry Expiry Date|Expiry Date|Expiration Date):\s*(.+)",
            "atualizado": r"(?:Updated Date|Last Updated):\s*(.+)",
            "status": r"(?:Domain Status):\s*(.+)",
            "name_server": r"(?:Name Server|Nameserver):\s*(.+)",
        }

        for campo, padrao in campos.items():
            matches = re.findall(padrao, texto, re.IGNORECASE)
            if matches:
                vals = [m.strip() for m in matches if m.strip()]
                resultado["campos"][campo] = vals if len(vals) > 1 else vals[0]

        for campo, valor in resultado["campos"].items():
            if isinstance(valor, list):
                _log(f"  {campo:12} : {', '.join(str(v) for v in valor[:3])}", "OK")
            else:
                _log(f"  {campo:12} : {valor}", "OK")

    except Exception as e:
        _log(f"WHOIS erro: {e}", "ERRO")
        resultado["erro"] = str(e)

    return resultado


# ==============================================================================
# MODULO: SSL/TLS
# ==============================================================================

def recon_ssl(dominio, porta=443, verbose=False):
    """Analisa o certificado SSL/TLS do servidor."""
    resultado = {
        "dominio": dominio,
        "porta": porta,
        "suportado": False,
        "certificado": {},
        "avisos": [],
    }

    try:
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE

        with socket.create_connection((dominio, porta), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()

                resultado["suportado"] = True
                resultado["protocolo"] = proto
                resultado["cipher"] = {"nome": cipher[0], "versao": cipher[1], "bits": cipher[2]}

                if cert:
                    # Sujeito
                    sujeito = {}
                    for item in cert.get("subject", []):
                        for k, v in item:
                            sujeito[k] = v
                    resultado["certificado"]["sujeito"] = sujeito

                    # Emitente
                    emitente = {}
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            emitente[k] = v
                    resultado["certificado"]["emitente"] = emitente

                    # Validade
                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")
                    resultado["certificado"]["valido_desde"] = not_before
                    resultado["certificado"]["valido_ate"] = not_after

                    # Verificar expiracao
                    if not_after:
                        try:
                            expira = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            agora = datetime.utcnow()
                            dias = (expira - agora).days
                            resultado["certificado"]["dias_restantes"] = dias
                            if dias < 0:
                                aviso = f"CERTIFICADO EXPIRADO ha {abs(dias)} dias!"
                                _log(aviso, "CRITICO")
                                resultado["avisos"].append(aviso)
                            elif dias < 30:
                                aviso = f"Certificado expira em {dias} dias!"
                                _log(aviso, "ALERTA")
                                resultado["avisos"].append(aviso)
                            else:
                                _log(f"Expira em: {not_after} ({dias} dias)", "OK")
                        except Exception:
                            pass

                    # SANs (Subject Alternative Names)
                    sans = []
                    for tipo, val in cert.get("subjectAltName", []):
                        sans.append(f"{tipo}:{val}")
                    resultado["certificado"]["san"] = sans
                    if sans:
                        _log(f"SANs: {len(sans)} entradas", "OK")
                        for san in sans[:5]:
                            _log(f"  {san}", "DEBUG", verbose_only=True, verbose=verbose)

                    # Verificar wildcard
                    wildcards = [s for s in sans if "DNS:*." in s]
                    resultado["certificado"]["wildcard"] = len(wildcards) > 0
                    if wildcards:
                        _log(f"Wildcard cert: {', '.join(wildcards)}", "INFO")

                    cn = sujeito.get("commonName", "")
                    _log(f"CN: {cn}", "OK")
                    _log(f"Emitido por: {emitente.get('organizationName', emitente.get('commonName', 'desconhecido'))}", "OK")
                    _log(f"Protocolo: {proto} | Cipher: {cipher[0]} ({cipher[2]} bits)", "OK")

                    # Verificar protocolos fracos
                    if proto in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        aviso = f"Protocolo fraco detectado: {proto}"
                        _log(aviso, "ALERTA")
                        resultado["avisos"].append(aviso)

                    # Verificar cipher fraco
                    if cipher[2] and cipher[2] < 128:
                        aviso = f"Cipher fraco: {cipher[0]} ({cipher[2]} bits)"
                        _log(aviso, "ALERTA")
                        resultado["avisos"].append(aviso)

    except ssl_lib.SSLError as e:
        _log(f"Erro SSL: {e}", "ERRO")
        resultado["erro"] = str(e)
    except ConnectionRefusedError:
        _log(f"Porta {porta} fechada", "INFO")
        resultado["erro"] = "Conexao recusada"
    except Exception as e:
        _log(f"SSL erro: {e}", "ERRO")
        resultado["erro"] = str(e)

    return resultado


# ==============================================================================
# MODULO: HTTP FINGERPRINTING + WAF + TECH + HEADERS
# ==============================================================================

def recon_http(url, stealth=False, proxy=None, timeout=10, verbose=False):
    """Fingerprinting HTTP completo: headers, WAF, tecnologias, redirects."""
    if not url.startswith("http"):
        url = "https://" + url
    resultado = {
        "url": url,
        "status": None,
        "server": None,
        "headers": {},
        "cookies": [],
        "redirects": [],
        "waf": [],
        "tecnologias": [],
        "seguranca": {},
    }

    if not REQUESTS_OK:
        _log("requests nao instalado - modulo HTTP limitado", "ALERTA")
        return resultado

    sess = _get_session(proxy, timeout)
    if not sess:
        return resultado

    headers_req = {
        "User-Agent": _get_ua(stealth),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    try:
        resp = sess.get(url, headers=headers_req, allow_redirects=True, timeout=timeout)
        resultado["status"] = resp.status_code
        resultado["headers"] = dict(resp.headers)
        resultado["cookies"] = [c.name for c in resp.cookies]

        # Rastrear redirecionamentos
        for r in resp.history:
            resultado["redirects"].append({
                "url": r.url,
                "status": r.status_code,
                "location": r.headers.get("location", ""),
            })

        server = resp.headers.get("server", "") or resp.headers.get("Server", "")
        resultado["server"] = server
        if server:
            _log(f"Server: {server}", "OK")

        powered_by = resp.headers.get("x-powered-by", "")
        if powered_by:
            _log(f"X-Powered-By: {powered_by}", "OK")

        _log(f"Status: {resp.status_code} | URL final: {resp.url}", "OK")

        if resultado["redirects"]:
            _log(f"Redirecionamentos: {len(resultado['redirects'])}", "INFO")
            for redir in resultado["redirects"]:
                _log(f"  {redir['status']} -> {redir['location']}", "DEBUG",
                     verbose_only=True, verbose=verbose)

        # Corpo da resposta (limitado)
        corpo = ""
        try:
            corpo = resp.text[:50000]
        except Exception:
            pass

        # Detectar WAF
        wafs = _detectar_waf(resp.headers, resultado["cookies"], server, corpo, verbose)
        resultado["waf"] = wafs

        # Detectar tecnologias
        techs = _detectar_tecnologias(resp.headers, resultado["cookies"], corpo, verbose)
        resultado["tecnologias"] = techs

        # Auditar headers de seguranca
        seg = _auditar_headers_seguranca(resp.headers, verbose)
        resultado["seguranca"] = seg

    except requests.exceptions.SSLError:
        _log(f"SSL invalido em {url} - tentando HTTP", "ALERTA")
        try:
            url_http = url.replace("https://", "http://")
            resp = sess.get(url_http, headers=headers_req, allow_redirects=True, timeout=timeout)
            resultado["status"] = resp.status_code
            resultado["url"] = url_http
        except Exception as e2:
            resultado["erro"] = str(e2)
    except Exception as e:
        _log(f"HTTP erro: {e}", "ERRO")
        resultado["erro"] = str(e)

    return resultado


def _detectar_waf(headers, cookies, server, corpo, verbose=False):
    """Detecta WAF/CDN com base em headers, cookies, server e corpo."""
    detectados = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    cookies_str = " ".join(cookies).lower()
    corpo_lower = corpo.lower() if corpo else ""
    server_lower = server.lower() if server else ""

    for nome, sigs in WAF_ASSINATURAS.items():
        score = 0
        evidencias = []

        for h in sigs.get("headers", []):
            if h.lower() in headers_lower:
                score += 2
                evidencias.append(f"header: {h}")

        for c in sigs.get("cookies", []):
            if c.lower() in cookies_str:
                score += 2
                evidencias.append(f"cookie: {c}")

        for s in sigs.get("server", []):
            if s.lower() in server_lower:
                score += 3
                evidencias.append(f"server: {s}")

        for b in sigs.get("body", []):
            if b.lower() in corpo_lower:
                score += 1
                evidencias.append(f"body: {b}")

        if score >= 2:
            detectados.append({"nome": nome, "score": score, "evidencias": evidencias})
            _log(f"WAF/CDN detectado: {nome} (score={score})", "ACHADO")
            for ev in evidencias:
                _log(f"  Evidencia: {ev}", "DEBUG", verbose_only=True, verbose=verbose)

    if not detectados:
        _log("Nenhum WAF/CDN reconhecido detectado", "INFO")

    return detectados


def _detectar_tecnologias(headers, cookies, corpo, verbose=False):
    """Detecta tecnologias (CMS, frameworks, linguagens)."""
    detectadas = []
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    cookies_str = " ".join(str(c) for c in cookies).lower()
    corpo_lower = corpo.lower() if corpo else ""

    for tech, sigs in TECH_ASSINATURAS.items():
        encontrado = False

        for h_key, h_pattern in sigs.get("headers_match", {}).items():
            h_val = headers_lower.get(h_key.lower(), "")
            if h_val and (h_pattern == "" or re.search(h_pattern, h_val, re.IGNORECASE)):
                encontrado = True
                break

        if not encontrado:
            for c in sigs.get("cookies", []):
                if c.lower() in cookies_str:
                    encontrado = True
                    break

        if not encontrado:
            for b in sigs.get("body", []):
                if b.lower() in corpo_lower:
                    encontrado = True
                    break

        if not encontrado:
            for m in sigs.get("meta", []):
                if m.lower() in corpo_lower:
                    encontrado = True
                    break

        if encontrado:
            detectadas.append(tech)
            _log(f"Tecnologia: {tech}", "OK")

    return detectadas


def _auditar_headers_seguranca(headers, verbose=False):
    """Audita headers de seguranca e reporta o que esta faltando."""
    resultado = {"presentes": {}, "ausentes": [], "score": 0, "max_score": 0}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    criticos = [k for k, v in HEADERS_SEGURANCA.items() if v["critico"]]
    total_criticos = len(criticos)

    for nome, info in HEADERS_SEGURANCA.items():
        resultado["max_score"] += 1
        nome_lower = nome.lower()
        val = headers_lower.get(nome_lower, "")

        if val:
            resultado["presentes"][nome] = val
            resultado["score"] += 1
            if verbose:
                _log(f"  [PRESENTE] {nome}: {val[:80]}", "OK")
            if info["regex_bom"] and not re.search(info["regex_bom"], val, re.IGNORECASE):
                _log(f"  Header {nome} presente mas valor subotimo: {val[:60]}", "ALERTA")
        else:
            resultado["ausentes"].append(nome)
            nivel = "ALERTA" if info["critico"] else "INFO"
            _log(f"  [AUSENTE] {nome} - {info['descricao']}", nivel)

    score_pct = int((resultado["score"] / resultado["max_score"]) * 100) if resultado["max_score"] > 0 else 0
    resultado["score_pct"] = score_pct

    if score_pct >= 80:
        _log(f"  Score de headers: {score_pct}% ({resultado['score']}/{resultado['max_score']}) - BOM", "OK")
    elif score_pct >= 50:
        _log(f"  Score de headers: {score_pct}% ({resultado['score']}/{resultado['max_score']}) - REGULAR", "ALERTA")
    else:
        _log(f"  Score de headers: {score_pct}% ({resultado['score']}/{resultado['max_score']}) - FRACO", "CRITICO")

    return resultado


# ==============================================================================
# MODULO: PORT SCANNER
# ==============================================================================

def _escanear_porta(args):
    host, porta, timeout = args
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((host, porta))
        if resultado == 0:
            # Banner grabbing
            banner = ""
            try:
                sock.settimeout(1.5)
                if porta in [80, 8080, 8000, 8008]:
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif porta == 21:
                    pass  # FTP manda banner automaticamente
                elif porta in [22, 23, 25, 110, 143]:
                    pass  # SSH/Telnet/SMTP/POP3/IMAP mandam banner
                data = sock.recv(512)
                banner = data.decode("utf-8", errors="ignore").strip()[:120]
            except Exception:
                pass
            sock.close()
            return (porta, True, banner)
        sock.close()
        return (porta, False, "")
    except Exception:
        return (porta, False, "")


def escanear_portas(host, portas=None, timeout=1.5, threads=100, verbose=False):
    """Varre portas TCP com banner grabbing em paralelo."""
    if portas is None:
        portas = PORTAS_COMUNS
    resultado = {"host": host, "abertas": [], "fechadas_total": 0}

    try:
        host_ip = socket.gethostbyname(host)
        resultado["ip"] = host_ip
        _log(f"IP resolvido: {host_ip}", "INFO")
    except Exception:
        host_ip = host

    args = [(host_ip, p, timeout) for p in portas]
    abertas = []
    concluido = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futuros = {executor.submit(_escanear_porta, a): a for a in args}
        for fut in concurrent.futures.as_completed(futuros):
            porta, aberta, banner = fut.result()
            concluido += 1
            _progresso(concluido, len(portas), prefixo="Portas:")
            if aberta:
                servico = PORTA_SERVICO.get(porta, "desconhecido")
                abertas.append({"porta": porta, "servico": servico, "banner": banner})

    _finalizar_progresso()

    abertas.sort(key=lambda x: x["porta"])
    resultado["abertas"] = abertas
    resultado["fechadas_total"] = len(portas) - len(abertas)

    if abertas:
        _log(f"{len(abertas)} porta(s) abertas em {host}:", "OK")
        for p in abertas:
            banner_info = f" | Banner: {p['banner'][:60]}" if p["banner"] else ""
            nivel = "CRITICO" if p["porta"] in [23, 1433, 3389, 5900, 11211, 6379, 27017] else "ACHADO"
            _log(f"  {p['porta']:5}/tcp  {p['servico']:25}{banner_info}", nivel)
    else:
        _log("Nenhuma porta aberta encontrada (portas scaneadas)", "INFO")

    return resultado


# ==============================================================================
# MODULO: SUBDOMAIN ENUMERATION
# ==============================================================================

def _testar_subdomain(args):
    dominio_base, sub = args
    fqdn = f"{sub}.{dominio_base}"
    try:
        ips = socket.gethostbyname_ex(fqdn)[2]
        if ips:
            return (fqdn, ips)
    except Exception:
        pass
    return None


def enumerar_subdomains(dominio, wordlist=None, threads=30, verbose=False):
    """Brute-force de subdomains via resolucao DNS em paralelo."""
    if wordlist is None:
        wordlist = SUBDOMAINS_LISTA
    resultado = {"dominio": dominio, "encontrados": [], "total_testados": len(wordlist)}

    args = [(dominio, sub) for sub in wordlist]
    encontrados = []
    concluido = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futuros = {executor.submit(_testar_subdomain, a): a for a in args}
        for fut in concurrent.futures.as_completed(futuros):
            concluido += 1
            _progresso(concluido, len(wordlist), prefixo="Subdomains:")
            res = fut.result()
            if res:
                fqdn, ips = res
                encontrados.append({"subdomain": fqdn, "ips": ips})

    _finalizar_progresso()
    encontrados.sort(key=lambda x: x["subdomain"])
    resultado["encontrados"] = encontrados

    if encontrados:
        _log(f"{len(encontrados)} subdomain(s) encontrado(s):", "OK")
        for s in encontrados:
            _log(f"  {s['subdomain']:45} -> {', '.join(s['ips'])}", "ACHADO")
    else:
        _log("Nenhum subdomain encontrado com a wordlist atual", "INFO")

    return resultado


# ==============================================================================
# MODULO: EMAIL SECURITY
# ==============================================================================

def verificar_email(dominio, verbose=False):
    """Verifica SPF, DKIM (seletores comuns), DMARC e MTA-STS."""
    resultado = {
        "dominio": dominio,
        "spf": None,
        "dmarc": None,
        "dkim": {},
        "mta_sts": None,
        "bimi": None,
        "problemas": [],
        "mx": [],
    }

    # MX records
    mx = _resolver_dns(dominio, "MX", verbose)
    if mx:
        resultado["mx"] = mx
        _log(f"MX: {', '.join(mx)}", "OK")
    else:
        _log("Sem registros MX", "INFO")

    # SPF
    txts = _resolver_dns(dominio, "TXT", verbose)
    spf = None
    for txt in txts:
        if "v=spf1" in txt.lower():
            spf = txt
            break
    resultado["spf"] = spf
    if spf:
        _log(f"SPF: {spf[:100]}", "OK")
        # Verificar permissoes perigosas
        if "+all" in spf.lower():
            p = "SPF com '+all' - aceita qualquer servidor (CRITICO!)"
            _log(p, "CRITICO")
            resultado["problemas"].append(p)
        elif "~all" in spf.lower():
            _log("SPF com '~all' (softfail) - OK mas prefer '-all'", "ALERTA")
        elif "-all" in spf.lower():
            _log("SPF com '-all' (hardfail) - configuracao correta", "OK")
        elif "?all" in spf.lower():
            p = "SPF com '?all' (neutro) - sem protecao"
            _log(p, "ALERTA")
            resultado["problemas"].append(p)
    else:
        p = "Sem registro SPF - dominio vulneravel a spoofing"
        _log(p, "CRITICO")
        resultado["problemas"].append(p)

    # DMARC
    dmarc_registros = _resolver_dns("_dmarc." + dominio, "TXT", verbose)
    dmarc = None
    for r in dmarc_registros:
        if "v=dmarc1" in r.lower():
            dmarc = r
            break
    resultado["dmarc"] = dmarc
    if dmarc:
        _log(f"DMARC: {dmarc[:100]}", "OK")
        if "p=none" in dmarc.lower():
            p = "DMARC p=none - somente monitoramento, sem protecao efetiva"
            _log(p, "ALERTA")
            resultado["problemas"].append(p)
        elif "p=quarantine" in dmarc.lower():
            _log("DMARC p=quarantine - emails suspeitos vao para spam", "OK")
        elif "p=reject" in dmarc.lower():
            _log("DMARC p=reject - protecao maxima habilitada", "OK")
        # Verificar RUA/RUF (relatorios)
        if "rua=" not in dmarc.lower():
            _log("DMARC sem RUA (relatorios agregados) configurado", "INFO")
    else:
        p = "Sem DMARC - dominio vulneravel a email spoofing"
        _log(p, "CRITICO")
        resultado["problemas"].append(p)

    # DKIM (seletores comuns)
    seletores_dkim = [
        "default", "google", "mail", "dkim", "k1", "k2", "s1", "s2",
        "selector1", "selector2", "key1", "key2", "em", "smtp",
        "mailjet", "mandrill", "sendgrid", "amazonses",
    ]
    for seletor in seletores_dkim:
        host_dkim = f"{seletor}._domainkey.{dominio}"
        registros = _resolver_dns(host_dkim, "TXT", verbose)
        for r in registros:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                resultado["dkim"][seletor] = r[:150]
                _log(f"DKIM seletor '{seletor}' encontrado", "OK")
                break

    if not resultado["dkim"]:
        _log("Nenhum seletor DKIM comum encontrado", "INFO")

    # MTA-STS
    mta_sts = _resolver_dns("_mta-sts." + dominio, "TXT", verbose)
    for r in mta_sts:
        if "v=sts1" in r.lower():
            resultado["mta_sts"] = r
            _log(f"MTA-STS: {r[:80]}", "OK")
            break
    if not resultado["mta_sts"]:
        _log("Sem MTA-STS (criptografia SMTP opcional nao enforced)", "INFO")

    # BIMI
    bimi = _resolver_dns("default._bimi." + dominio, "TXT", verbose)
    for r in bimi:
        if "v=bimi1" in r.lower():
            resultado["bimi"] = r
            _log(f"BIMI: configurado", "INFO")
            break

    # Score resumo
    score = 0
    if resultado["spf"] and "-all" in str(resultado["spf"]).lower():
        score += 1
    if resultado["dmarc"] and "p=reject" in str(resultado["dmarc"]).lower():
        score += 1
    elif resultado["dmarc"] and "p=quarantine" in str(resultado["dmarc"]).lower():
        score += 1
    if resultado["dkim"]:
        score += 1
    if resultado["mta_sts"]:
        score += 1

    niveis = {0: ("CRITICO - email spoofing trivial", "CRITICO"),
              1: ("FRACO - protecao parcial", "ALERTA"),
              2: ("REGULAR - melhorias necessarias", "ALERTA"),
              3: ("BOM - protecao adequada", "OK"),
              4: ("EXCELENTE - protecao completa", "OK")}
    msg, nivel = niveis.get(score, ("Desconhecido", "INFO"))
    _log(f"Score email security: {score}/4 - {msg}", nivel)
    resultado["score"] = score

    return resultado


# ==============================================================================
# MODULO: CERTIFICATE TRANSPARENCY LOGS
# ==============================================================================

def buscar_ct_logs(dominio, limite=100, verbose=False):
    """Busca certificados emitidos para o dominio no crt.sh."""
    resultado = {"dominio": dominio, "certificados": [], "subdomains_ct": []}

    try:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(dominio)}&output=json"
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENTS[0],
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=20) as resp:
            dados = json.loads(resp.read().decode("utf-8", errors="ignore"))

        _log(f"{len(dados)} certificados encontrados no CT log", "OK")

        vistos = set()
        certs_unicos = []
        subdomains_ct = set()

        for cert in dados[:limite]:
            nome_comum = cert.get("common_name", "")
            nome_value = cert.get("name_value", "")
            emitente = cert.get("issuer_name", "")
            log_at = cert.get("entry_timestamp", "")[:10]

            # Extrair subdomains dos SANs
            for linha in nome_value.split("\n"):
                linha = linha.strip().lstrip("*.")
                if linha.endswith(dominio) and linha not in vistos:
                    subdomains_ct.add(linha)

            chave = (nome_comum, emitente[:50])
            if chave not in vistos:
                vistos.add(chave)
                certs_unicos.append({
                    "common_name": nome_comum,
                    "emitente": emitente[:80],
                    "data": log_at,
                    "san": nome_value[:200],
                })

        resultado["certificados"] = certs_unicos[:50]
        resultado["subdomains_ct"] = sorted(subdomains_ct)

        if resultado["subdomains_ct"]:
            _log(f"{len(resultado['subdomains_ct'])} subdomain(s) via CT logs:", "ACHADO")
            for sub in resultado["subdomains_ct"][:20]:
                _log(f"  {sub}", "OK")
            if len(resultado["subdomains_ct"]) > 20:
                _log(f"  ... e mais {len(resultado['subdomains_ct']) - 20}", "INFO")

        if certs_unicos:
            _log(f"Ultimos certificados emitidos:", "INFO")
            for cert in certs_unicos[:5]:
                _log(f"  {cert['data']} | CN={cert['common_name']} | {cert['emitente'][:50]}", "INFO")

    except Exception as e:
        _log(f"CT logs erro: {e}", "ERRO")
        resultado["erro"] = str(e)

    return resultado


# ==============================================================================
# MODULO: ASN / BGP
# ==============================================================================

def recon_asn(dominio, verbose=False):
    resultado = {"dominio": dominio, "ip": None, "asn": None, "org": None,
                 "country": None, "city": None, "cidr": []}
    try:
        ip = socket.gethostbyname(dominio)
        resultado["ip"] = ip
    except Exception:
        _log("Nao foi possivel resolver IP para lookup ASN", "ERRO")
        return resultado
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENTS[0], "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        parts = data.get("org", "").split(" ", 1)
        resultado["asn"]     = parts[0] if parts else None
        resultado["org"]     = parts[1] if len(parts) > 1 else None
        resultado["country"] = data.get("country")
        resultado["city"]    = data.get("city")
        resultado["region"]  = data.get("region")
        resultado["hostname"]= data.get("hostname")
        if data.get("org"):
            _log(f"ASN: {data['org']}", "OK")
        if data.get("country"):
            _log(f"Pais/Cidade: {data.get('country')}/{data.get('city','?')}", "OK")
        if data.get("hostname"):
            _log(f"Hostname PTR: {data['hostname']}", "INFO")
    except Exception as e:
        _log(f"ipinfo.io erro: {e}", "INFO")
    asn_num = resultado.get("asn", "") or ""
    if asn_num.startswith("AS"):
        try:
            url2 = f"https://api.bgpview.io/asn/{asn_num[2:]}/prefixes"
            req2 = urllib.request.Request(
                url2, headers={"User-Agent": USER_AGENTS[0], "Accept": "application/json"})
            with urllib.request.urlopen(req2, timeout=10) as resp2:
                d2 = json.loads(resp2.read().decode())
            if d2.get("status") == "ok":
                pref = d2.get("data", {}).get("ipv4_prefixes", [])
                cidrs = [p.get("prefix") for p in pref[:20] if p.get("prefix")]
                resultado["cidr"] = cidrs
                if cidrs:
                    _log(f"CIDRs IPv4 ({len(cidrs)}): {', '.join(cidrs[:6])}", "OK")
        except Exception:
            pass
    return resultado


# ==============================================================================
# MODULO: CLOUD BUCKET DISCOVERY
# ==============================================================================

_BUCKET_SUFIXOS = [
    "", "www", "static", "assets", "media", "images", "img", "files",
    "backup", "backups", "data", "dev", "staging", "test", "api", "cdn",
    "upload", "uploads", "docs", "public", "storage", "app", "web", "logs",
]


def recon_s3_buckets(dominio, verbose=False):
    resultado = {"dominio": dominio, "encontrados": []}
    nome_base = dominio.split(".")[0]
    nomes = {dominio.replace(".", "-"), nome_base}
    for suf in _BUCKET_SUFIXOS:
        if suf:
            nomes.update([
                f"{nome_base}-{suf}", f"{nome_base}.{suf}",
                f"{suf}.{nome_base}", f"{suf}-{nome_base}",
            ])
    endpoints = []
    for nome in list(nomes)[:40]:
        endpoints.append(("AWS S3",  f"https://{nome}.s3.amazonaws.com"))
        endpoints.append(("AWS S3",  f"https://s3.amazonaws.com/{nome}"))
        endpoints.append(("GCS",     f"https://storage.googleapis.com/{nome}"))
        endpoints.append(("Azure",   f"https://{nome}.blob.core.windows.net"))
    _log(f"Testando {len(endpoints)} endpoints de cloud storage...", "INFO")
    encontrados = []
    for plataforma, url in endpoints[:80]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENTS[0]})
            with urllib.request.urlopen(req, timeout=4) as resp:
                status = resp.status
                corpo  = resp.read(2048).decode("utf-8", errors="ignore")
                if status in [200, 403]:
                    listavel = (status == 200 and
                                any(k in corpo for k in
                                    ["ListBucketResult", "<Contents>", "<?xml"]))
                    nivel = "CRITICO" if listavel else "ACHADO"
                    _log(f"{'BUCKET LISTAVEL' if listavel else 'Bucket existe'}: "
                         f"[{plataforma}] {url}", nivel)
                    encontrados.append({"plataforma": plataforma, "url": url,
                                        "status": status, "listavel": listavel})
        except Exception:
            pass
    resultado["encontrados"] = encontrados
    if not encontrados:
        _log("Nenhum bucket exposto encontrado", "INFO")
    return resultado


# ==============================================================================
# MODULO: CORS MISCONFIGURATION
# ==============================================================================

def recon_cors(url, stealth=False, proxy=None, timeout=10, verbose=False):
    resultado = {"url": url, "vulneravel": False, "detalhes": []}
    if not REQUESTS_OK:
        _log("requests nao instalado - CORS check indisponivel", "ALERTA")
        return resultado
    if not url.startswith("http"):
        url = "https://" + url
    sess = _get_session(proxy, timeout)
    ua   = _get_ua(stealth)
    alvo_dom = url.split("/")[2] if "/" in url else url
    origens = [
        "https://evil.com",
        "https://attacker.com",
        f"https://evil.{alvo_dom}",
        "null",
        "http://localhost",
    ]
    for origem in origens:
        try:
            r    = sess.get(url, headers={"User-Agent": ua, "Origin": origem}, timeout=timeout)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            creds= r.headers.get("Access-Control-Allow-Credentials", "").lower()
            if not acao:
                continue
            if acao == "*":
                _log("CORS wildcard (*) — qualquer origem permitida", "ALERTA")
                resultado["detalhes"].append({"origem": origem, "acao": acao,
                                              "credentials": creds, "nivel": "MEDIO"})
                resultado["vulneravel"] = True
            elif acao == origem or acao == "null":
                nivel = "CRITICO" if creds == "true" else "ALTO"
                msg   = f"CORS reflete origem '{origem}'"
                if creds == "true":
                    msg += " + credentials=true (leitura de cookies!)"
                _log(msg, nivel)
                resultado["detalhes"].append({"origem": origem, "acao": acao,
                                              "credentials": creds, "nivel": nivel})
                resultado["vulneravel"] = True
        except Exception:
            pass
    if not resultado["vulneravel"]:
        _log("Nenhuma misconfiguracao CORS critica detectada", "INFO")
    return resultado


# ==============================================================================
# MODULO: JS ENDPOINT EXTRACTION
# ==============================================================================

def extrair_endpoints_js(url, stealth=False, proxy=None, timeout=10, verbose=False):
    resultado = {"url": url, "endpoints": [], "js_files": []}
    if not REQUESTS_OK:
        return resultado
    if not url.startswith("http"):
        url = "https://" + url
    sess = _get_session(proxy, timeout)
    ua   = _get_ua(stealth)
    try:
        r    = sess.get(url, headers={"User-Agent": ua}, timeout=timeout)
        html = r.text
    except Exception as e:
        _log(f"Erro ao buscar pagina para extrator JS: {e}", "ERRO")
        return resultado
    base_url = "/".join(url.split("/")[:3])
    js_refs  = re.findall(r'src=["\']([^"\']+\.js[^"\']{0,60})["\']', html, re.IGNORECASE)
    js_urls  = []
    for js in js_refs[:20]:
        if js.startswith("http"):
            js_urls.append(js)
        elif js.startswith("/"):
            js_urls.append(base_url + js)
        else:
            js_urls.append(url.rstrip("/") + "/" + js)
    resultado["js_files"] = js_urls[:15]
    _log(f"Arquivos JS encontrados: {len(js_urls)}", "INFO")
    padroes = [
        r'["\'](/api/[^"\'<>\s]{2,80})["\']',
        r'fetch\(["\']([^"\'<>\s]{2,80})["\']',
        r'axios\.[a-z]+\(["\']([^"\'<>\s]{2,80})["\']',
        r'\.(?:get|post|put|delete)\(["\']([^"\'<>\s]{2,60})["\']',
        r'url\s*[:=]\s*["\']([^"\'<>\s]{2,80})["\']',
        r'endpoint\s*[:=]\s*["\']([^"\'<>\s]{2,80})["\']',
        r'path\s*[:=]\s*["\']([/][^"\'<>\s]{1,60})["\']',
        r'["\'](https?://[^"\'<>\s]{10,100})["\']',
    ]
    eps = set()
    for p in padroes:
        eps.update(re.findall(p, html, re.IGNORECASE)[:30])
    for js_url in js_urls[:10]:
        try:
            r_js = sess.get(js_url, headers={"User-Agent": ua}, timeout=timeout)
            content = r_js.text[:400000]
            for p in padroes:
                eps.update(re.findall(p, content, re.IGNORECASE)[:40])
        except Exception:
            pass
    limpos = sorted({e for e in eps
                     if len(e) > 3 and "/" in e
                     and not e.endswith((".js", ".css", ".png", ".jpg", ".ico"))})[:100]
    resultado["endpoints"] = limpos
    if limpos:
        _log(f"{len(limpos)} endpoint(s) extraido(s) de JS:", "ACHADO")
        for ep in limpos[:15]:
            _log(f"  {ep}", "OK")
        if len(limpos) > 15:
            _log(f"  ... e mais {len(limpos) - 15}", "INFO")
    else:
        _log("Nenhum endpoint JS encontrado", "INFO")
    return resultado


# ==============================================================================
# MODULO: SHODAN
# ==============================================================================

def recon_shodan(ip, api_key, verbose=False):
    resultado = {"ip": ip, "ports": [], "cves": [], "tags": [], "hostnames": []}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENTS[0], "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        resultado.update({
            "ports":     data.get("ports", []),
            "tags":      data.get("tags", []),
            "hostnames": data.get("hostnames", []),
            "org":       data.get("org", ""),
            "os":        data.get("os", ""),
            "country":   data.get("country_name", ""),
        })
        vulns = data.get("vulns", {})
        resultado["cves"] = list(vulns.keys()) if isinstance(vulns, dict) else list(vulns)
        if resultado["ports"]:
            _log(f"Portas Shodan: {', '.join(str(p) for p in resultado['ports'][:20])}", "ACHADO")
        if resultado["hostnames"]:
            _log(f"Hostnames: {', '.join(resultado['hostnames'][:5])}", "OK")
        if resultado["tags"]:
            _log(f"Tags: {', '.join(resultado['tags'])}", "INFO")
        if resultado["cves"]:
            _log(f"CVEs Shodan: {len(resultado['cves'])} vulnerabilidade(s)", "CRITICO")
            for cve in resultado["cves"][:8]:
                _log(f"  {cve}", "ALERTA")
        for item in data.get("data", [])[:3]:
            porta = item.get("port")
            prod  = item.get("product", "")
            ver   = item.get("version", "")
            if porta and prod:
                _log(f"  Servico {porta}: {prod} {ver}", "INFO")
    except Exception as e:
        msg = str(e)
        if "401" in msg or "403" in msg:
            _log("Shodan: API key invalida ou sem creditos", "ERRO")
        else:
            _log(f"Shodan erro: {e}", "ERRO")
    return resultado


# ==============================================================================
# MODULO: OPEN REDIRECT
# ==============================================================================

_OR_PARAMS = [
    "url", "redirect", "redirect_url", "return", "return_url", "next",
    "next_url", "goto", "destination", "dest", "redir", "r", "u",
    "link", "out", "target", "forward", "location", "go", "continue",
    "back", "returnUrl", "redirectUrl", "returnTo", "successUrl",
]
_OR_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2f%2e%2e",
    "/\\evil.com",
]


def testar_open_redirect(url, stealth=False, proxy=None, timeout=8, verbose=False):
    resultado = {"url": url, "vulneravel": False, "achados": []}
    if not REQUESTS_OK:
        return resultado
    if not url.startswith("http"):
        url = "https://" + url
    sess = _get_session(proxy, timeout)
    ua   = _get_ua(stealth)
    base = url.rstrip("/")
    _log(f"Testando {len(_OR_PARAMS)} parametros de redirect...", "INFO")
    for param in _OR_PARAMS[:15]:
        for payload in _OR_PAYLOADS:
            test_url = f"{base}?{param}={urllib.parse.quote(payload, safe='')}"
            try:
                r = sess.get(test_url, allow_redirects=False, timeout=timeout,
                             headers={"User-Agent": ua})
                loc = r.headers.get("location", "") or r.headers.get("Location", "")
                if loc and ("evil.com" in loc or loc.startswith("//")):
                    resultado["achados"].append({
                        "param": param, "payload": payload,
                        "status": r.status_code, "location": loc,
                    })
                    resultado["vulneravel"] = True
                    _log(f"Open Redirect: ?{param}={payload[:30]} -> {loc}", "CRITICO")
            except Exception:
                pass
    if not resultado["vulneravel"]:
        _log("Nenhum open redirect detectado", "INFO")
    return resultado


# ==============================================================================
# MODULO: PASSIVE DNS
# ==============================================================================

def passive_dns(dominio, vt_key=None, verbose=False):
    resultado = {"dominio": dominio, "subdomains": []}
    if not vt_key:
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(dominio)}"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENTS[0]})
            with urllib.request.urlopen(req, timeout=15) as resp:
                texto = resp.read().decode("utf-8", errors="ignore")
            subs = []
            for linha in texto.strip().split("\n"):
                if "," in linha and not linha.startswith("error"):
                    sub, ip2 = linha.split(",", 1)
                    sub = sub.strip(); ip2 = ip2.strip()
                    if sub.endswith(dominio):
                        subs.append({"subdomain": sub, "ip": ip2})
            resultado["subdomains"] = subs
            if subs:
                _log(f"{len(subs)} subdomains via HackerTarget passive DNS:", "ACHADO")
                for s in subs[:15]:
                    _log(f"  {s['subdomain']:45} -> {s['ip']}", "OK")
            else:
                _log("Passive DNS: sem resultados (HackerTarget)", "INFO")
        except Exception as e:
            _log(f"HackerTarget passive DNS erro: {e}", "ERRO")
        return resultado
    try:
        url = (f"https://www.virustotal.com/api/v3/domains/"
               f"{urllib.parse.quote(dominio)}/subdomains?limit=40")
        req = urllib.request.Request(url, headers={"x-apikey": vt_key,
                                                   "User-Agent": USER_AGENTS[0]})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        subs = [{"subdomain": item.get("id", ""), "ip": ""}
                for item in data.get("data", []) if item.get("id")]
        resultado["subdomains"] = subs
        _log(f"{len(subs)} subdomains via VirusTotal passive DNS:", "ACHADO")
        for s in subs[:20]:
            _log(f"  {s['subdomain']}", "OK")
    except Exception as e:
        _log(f"VirusTotal passive DNS erro: {e}", "ERRO")
    return resultado


# ==============================================================================
# MODULO: RELATORIO HTML
# ==============================================================================

def gerar_relatorio_html(resultados, output_file):
    alvo = resultados.get("alvo", "")
    ts   = resultados.get("timestamp", "")
    secoes = []

    def _tbl(itens, colunas):
        if not itens:
            return "<p class='vazio'>Nenhum resultado.</p>"
        h    = "".join(f"<th>{c}</th>" for c in colunas)
        rows = "".join(
            "<tr>" + "".join(f"<td>{str(i.get(c,''))}</td>" for c in colunas) + "</tr>"
            for i in itens
        )
        return f"<table><thead><tr>{h}</tr></thead><tbody>{rows}</tbody></table>"

    if "asn" in resultados:
        d = resultados["asn"]
        itens = [{"campo": k, "valor": str(v)} for k, v in d.items() if k != "cidr"]
        if d.get("cidr"):
            itens.append({"campo": "CIDRs", "valor": ", ".join(d["cidr"][:8])})
        secoes.append(f"<section><h2>ASN / BGP</h2>{_tbl(itens, ['campo','valor'])}</section>")

    if "dns" in resultados:
        regs  = resultados["dns"].get("registros", {})
        itens = [{"tipo": k, "valor": ", ".join(v[:3])} for k, v in regs.items()]
        secoes.append(f"<section><h2>DNS</h2>{_tbl(itens, ['tipo','valor'])}</section>")

    if "ssl" in resultados:
        d    = resultados["ssl"]
        cert = d.get("certificado", {})
        itens = [
            {"campo": "Protocolo",       "valor": d.get("protocolo", "")},
            {"campo": "Expira",          "valor": cert.get("valido_ate", "")},
            {"campo": "Dias restantes",  "valor": cert.get("dias_restantes", "")},
            {"campo": "CN",              "valor": cert.get("sujeito", {}).get("commonName", "")},
            {"campo": "SANs",            "valor": ", ".join(cert.get("sans", [])[:6])},
        ]
        secoes.append(f"<section><h2>SSL/TLS</h2>{_tbl(itens, ['campo','valor'])}</section>")

    if "http" in resultados:
        d         = resultados["http"]
        wafs      = d.get("waf", [])
        techs     = d.get("tecnologias", [])
        seg       = d.get("seguranca", {})
        ausentes  = seg.get("ausentes", []) if seg else []
        score_pct = seg.get("score_pct", 0) if seg else 0
        h = (f"<p><b>WAF/CDN:</b> {', '.join(w['nome'] for w in wafs) if wafs else 'Nenhum'}</p>"
             f"<p><b>Tecnologias:</b> {', '.join(techs) if techs else 'N/D'}</p>"
             f"<p><b>Security Headers Score:</b> {score_pct}%</p>"
             + (f"<p><b>Headers ausentes:</b> {', '.join(ausentes)}</p>" if ausentes else ""))
        secoes.append(f"<section><h2>HTTP Fingerprinting</h2>{h}</section>")

    if "portas" in resultados:
        abertas = resultados["portas"].get("abertas", [])
        secoes.append(f"<section><h2>Portas Abertas ({len(abertas)})</h2>"
                      f"{_tbl(abertas, ['porta','servico','banner'])}</section>")

    if "subdomains" in resultados:
        subs  = resultados["subdomains"].get("encontrados", [])
        itens = [{"subdomain": s["subdomain"], "ips": ", ".join(s.get("ips", []))} for s in subs]
        secoes.append(f"<section><h2>Subdomains ({len(subs)})</h2>"
                      f"{_tbl(itens, ['subdomain','ips'])}</section>")

    if "cors" in resultados and resultados["cors"].get("vulneravel"):
        dets = resultados["cors"].get("detalhes", [])
        secoes.append(f"<section><h2>CORS <span class='badge critico'>VULNERAVEL</span></h2>"
                      f"{_tbl(dets, ['origem','acao','nivel'])}</section>")

    if "js_endpoints" in resultados:
        eps = resultados["js_endpoints"].get("endpoints", [])
        secoes.append(f"<section><h2>JS Endpoints ({len(eps)})</h2>"
                      f"{_tbl([{'endpoint': e} for e in eps[:50]], ['endpoint'])}</section>")

    if "open_redirect" in resultados and resultados["open_redirect"].get("vulneravel"):
        achados = resultados["open_redirect"].get("achados", [])
        secoes.append(f"<section><h2>Open Redirect <span class='badge critico'>VULNERAVEL</span></h2>"
                      f"{_tbl(achados, ['param','payload','status','location'])}</section>")

    if "shodan" in resultados:
        d     = resultados["shodan"]
        itens = [
            {"campo": "Org",    "valor": d.get("org", "")},
            {"campo": "OS",     "valor": d.get("os", "")},
            {"campo": "Pais",   "valor": d.get("country", "")},
            {"campo": "Portas", "valor": ", ".join(str(p) for p in d.get("ports", []))},
            {"campo": "CVEs",   "valor": ", ".join(d.get("cves", [])[:5])},
        ]
        secoes.append(f"<section><h2>Shodan</h2>{_tbl(itens, ['campo','valor'])}</section>")

    if "ct_logs" in resultados:
        ct_subs = resultados["ct_logs"].get("subdomains_ct", [])
        secoes.append(f"<section><h2>CT Logs ({len(ct_subs)} subdomains)</h2>"
                      f"{_tbl([{'subdomain': s} for s in ct_subs[:50]], ['subdomain'])}</section>")

    html = (
        "<!DOCTYPE html>\n<html lang='pt-BR'>\n<head>\n"
        "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>\n"
        f"<title>Ghost-Recon | {alvo}</title>\n"
        "<style>\n"
        "body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}\n"
        "h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:10px}\n"
        "h2{color:#79c0ff;margin-top:0}\n"
        "table{width:100%;border-collapse:collapse;margin-top:8px}\n"
        "th{background:#161b22;color:#58a6ff;padding:7px;text-align:left;border:1px solid #30363d}\n"
        "td{padding:5px 8px;border:1px solid #21262d;word-break:break-all;font-size:.9em}\n"
        "tr:nth-child(even){background:#161b22}\n"
        "section{background:#161b22;border:1px solid #30363d;border-radius:6px;"
        "padding:14px;margin-bottom:16px}\n"
        ".badge{padding:2px 8px;border-radius:3px;font-size:.75em;margin-left:8px}\n"
        ".critico{background:#da3633;color:#fff}\n"
        ".vazio{color:#6e7681;font-style:italic;font-size:.9em}\n"
        ".meta{color:#8b949e;font-size:.85em;margin-bottom:16px}\n"
        "</style></head>\n<body>\n"
        f"<h1>Ghost-Recon v{VERSAO} | {alvo}</h1>\n"
        f"<p class='meta'>Scan: {ts}</p>\n"
        + "".join(secoes)
        + "\n<footer style='margin-top:32px;color:#6e7681;font-size:.8em'>"
          "By Gh0st-Bx1 | github.com/Ghost-Bx1</footer>\n</body>\n</html>"
    )
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        _log(f"Relatorio HTML salvo: {output_file}", "OK")
    except Exception as e:
        _log(f"Erro ao salvar HTML: {e}", "ERRO")


# ==============================================================================
# RELATORIO
# ==============================================================================

def gerar_relatorio(resultados, output_file, verbose=False):
    """Salva resultado completo em JSON."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(resultados, f, indent=2, default=str, ensure_ascii=False)
        _log(f"Relatorio salvo em: {output_file}", "OK")
    except Exception as e:
        _log(f"Erro ao salvar relatorio: {e}", "ERRO")


# ==============================================================================
# ORQUESTRADOR PRINCIPAL
# ==============================================================================

def escanear(dominio, args):
    """Executa os modulos selecionados e consolida resultados."""
    dominio_limpo = dominio.replace("https://", "").replace("http://", "").split("/")[0]
    url = f"https://{dominio_limpo}"

    resultados = {
        "alvo": dominio_limpo,
        "url": url,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "versao": VERSAO,
    }

    executar_tudo = args.completo

    # DNS
    if executar_tudo or args.dns:
        _secao("DNS RECON")
        resultados["dns"] = recon_dns(dominio_limpo, verbose=args.verbose)

    # WHOIS
    if executar_tudo or args.whois:
        _secao("WHOIS")
        resultados["whois"] = recon_whois(dominio_limpo, verbose=args.verbose)

    # SSL/TLS
    if executar_tudo or args.ssl:
        _secao("SSL/TLS")
        porta_ssl = 443
        resultados["ssl"] = recon_ssl(dominio_limpo, porta=porta_ssl, verbose=args.verbose)

    # HTTP Fingerprinting (inclui WAF, tech, headers se --completo)
    if executar_tudo or args.http or args.waf or args.tech or args.headers:
        _secao("HTTP FINGERPRINTING")
        r_http = recon_http(
            url,
            stealth=args.stealth,
            proxy=args.proxy,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        resultados["http"] = r_http

        if not (executar_tudo or args.waf):
            r_http.pop("waf", None)
        if not (executar_tudo or args.tech):
            r_http.pop("tecnologias", None)
        if not (executar_tudo or args.headers):
            r_http.pop("seguranca", None)

    # Port Scanner
    if executar_tudo or args.portas:
        _secao("PORT SCANNER")
        portas = PORTAS_COMUNS
        if hasattr(args, "portas_lista") and args.portas_lista:
            try:
                portas = [int(p.strip()) for p in args.portas_lista.split(",")]
            except ValueError:
                _log("Lista de portas invalida - usando padrao", "ALERTA")
        elif hasattr(args, "portas_top50") and args.portas_top50:
            portas = PORTAS_COMUNS[:50]
        resultados["portas"] = escanear_portas(
            dominio_limpo, portas=portas,
            timeout=args.timeout, threads=args.threads,
            verbose=args.verbose,
        )

    # Subdomain Enumeration
    if executar_tudo or args.subdomains:
        _secao("SUBDOMAIN ENUMERATION")
        wordlist = SUBDOMAINS_LISTA
        if hasattr(args, "wordlist") and args.wordlist:
            try:
                with open(args.wordlist, "r") as f:
                    wordlist = [l.strip() for l in f if l.strip()]
                _log(f"Wordlist: {len(wordlist)} entradas de {args.wordlist}", "INFO")
            except Exception as e:
                _log(f"Erro ao ler wordlist: {e} - usando lista interna", "ALERTA")
        resultados["subdomains"] = enumerar_subdomains(
            dominio_limpo, wordlist=wordlist,
            threads=args.threads, verbose=args.verbose,
        )

    # Email Security
    if executar_tudo or args.email:
        _secao("EMAIL SECURITY")
        resultados["email"] = verificar_email(dominio_limpo, verbose=args.verbose)

    # CT Logs
    if executar_tudo or args.ct:
        _secao("CERTIFICATE TRANSPARENCY LOGS")
        limite = getattr(args, "ct_limite", 100)
        resultados["ct_logs"] = buscar_ct_logs(dominio_limpo, limite=limite, verbose=args.verbose)

    # ASN / BGP
    if executar_tudo or getattr(args, "asn", False):
        _secao("ASN / BGP")
        resultados["asn"] = recon_asn(dominio_limpo, verbose=args.verbose)

    # Cloud Buckets
    if executar_tudo or getattr(args, "s3", False):
        _secao("CLOUD BUCKET DISCOVERY")
        resultados["s3_buckets"] = recon_s3_buckets(dominio_limpo, verbose=args.verbose)

    # CORS
    if executar_tudo or getattr(args, "cors", False):
        _secao("CORS MISCONFIGURATION")
        resultados["cors"] = recon_cors(url, stealth=args.stealth, proxy=args.proxy,
                                        timeout=args.timeout, verbose=args.verbose)

    # JS Endpoints
    if executar_tudo or getattr(args, "js", False):
        _secao("JS ENDPOINT EXTRACTION")
        resultados["js_endpoints"] = extrair_endpoints_js(
            url, stealth=args.stealth, proxy=args.proxy,
            timeout=args.timeout, verbose=args.verbose)

    # Shodan
    shodan_key = getattr(args, "shodan_key", None)
    if shodan_key:
        _secao("SHODAN LOOKUP")
        try:
            ip_alvo = socket.gethostbyname(dominio_limpo)
            resultados["shodan"] = recon_shodan(ip_alvo, shodan_key, verbose=args.verbose)
        except Exception as e:
            _log(f"Shodan resolve erro: {e}", "ERRO")

    # Open Redirect
    if getattr(args, "openredirect", False):
        _secao("OPEN REDIRECT SCAN")
        resultados["open_redirect"] = testar_open_redirect(
            url, stealth=args.stealth, proxy=args.proxy,
            timeout=args.timeout, verbose=args.verbose)

    # Passive DNS
    if getattr(args, "passivedns", False):
        _secao("PASSIVE DNS")
        vt_key = getattr(args, "vt_key", None)
        resultados["passive_dns"] = passive_dns(dominio_limpo, vt_key=vt_key,
                                                verbose=args.verbose)

    # Sumario final
    _secao("SUMARIO")
    _imprimir_sumario(resultados, dominio_limpo)

    return resultados


def _imprimir_sumario(resultados, dominio):
    _log(f"Alvo: {dominio}", "TITULO")
    _log(f"Timestamp: {resultados['timestamp']}", "INFO")

    if "dns" in resultados:
        registros = resultados["dns"].get("registros", {})
        a_records = registros.get("A", [])
        if a_records:
            _log(f"IPs A records: {', '.join(a_records[:5])}", "OK")

    if "ssl" in resultados:
        ssl_data = resultados["ssl"]
        if ssl_data.get("suportado"):
            dias = ssl_data.get("certificado", {}).get("dias_restantes", "?")
            proto = ssl_data.get("protocolo", "?")
            _log(f"SSL: {proto} | Expira em {dias} dias", "OK")
        for av in ssl_data.get("avisos", []):
            _log(f"SSL AVISO: {av}", "ALERTA")

    if "http" in resultados:
        http_data = resultados["http"]
        wafs = http_data.get("waf", [])
        techs = http_data.get("tecnologias", [])
        seg = http_data.get("seguranca", {})
        if wafs:
            _log(f"WAF/CDN: {', '.join(w['nome'] for w in wafs)}", "OK")
        if techs:
            _log(f"Tecnologias: {', '.join(techs[:8])}", "OK")
        score_pct = seg.get("score_pct", 0) if seg else 0
        ausentes = seg.get("ausentes", []) if seg else []
        if ausentes:
            _log(f"Headers faltando: {', '.join(ausentes[:4])}", "ALERTA")

    if "portas" in resultados:
        abertas = resultados["portas"].get("abertas", [])
        if abertas:
            _log(f"Portas abertas: {', '.join(str(p['porta']) for p in abertas)}", "ACHADO")

    if "subdomains" in resultados:
        subs = resultados["subdomains"].get("encontrados", [])
        _log(f"Subdomains: {len(subs)} encontrados", "OK" if subs else "INFO")

    if "email" in resultados:
        email_data = resultados["email"]
        problemas = email_data.get("problemas", [])
        for p in problemas[:3]:
            _log(f"Email: {p}", "ALERTA")

    if "ct_logs" in resultados:
        ct_subs = resultados["ct_logs"].get("subdomains_ct", [])
        _log(f"CT logs: {len(ct_subs)} subdomains via certificados", "OK" if ct_subs else "INFO")


# ==============================================================================
# CLI
# ==============================================================================

def main():
    if not REQUESTS_OK:
        print(f"{C['Y']}[!] Modulo 'requests' nao instalado. Instale com: pip install requests{C['X']}")
    if not DNS_OK:
        print(f"{C['D']}[D] Modulo 'dnspython' nao instalado (opcional). Usando DNS-over-HTTPS como fallback.{C['X']}")

    parser = argparse.ArgumentParser(
        prog="ghost-recon",
        description="Ghost-Recon v{} - Framework de Reconhecimento Ofensivo | By Gh0st-Bx1".format(VERSAO),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python ghost-recon.py -d exemplo.com\n"
            "  python ghost-recon.py -d exemplo.com --completo\n"
            "  python ghost-recon.py -d exemplo.com --dns --ssl --http --headers\n"
            "  python ghost-recon.py -d exemplo.com --subdomains --threads 30\n"
            "  python ghost-recon.py -d exemplo.com --portas --portas-lista '80,443,8080'\n"
            "  python ghost-recon.py -d exemplo.com --completo --output resultado.json\n"
            "  python ghost-recon.py -d exemplo.com --stealth --proxy http://127.0.0.1:8080\n"
        ),
    )

    parser.add_argument("-d", "--dominio", required=True,
                        help="Dominio ou IP alvo (ex: exemplo.com)")

    # Modulos
    grp = parser.add_argument_group("Modulos de reconhecimento")
    grp.add_argument("--completo", action="store_true",
                     help="Executar todos os modulos")
    grp.add_argument("--dns", action="store_true",
                     help="Enumeracao DNS (A/AAAA/MX/NS/TXT/SOA/CAA)")
    grp.add_argument("--whois", action="store_true",
                     help="Consulta WHOIS")
    grp.add_argument("--ssl", action="store_true",
                     help="Analise SSL/TLS e certificado")
    grp.add_argument("--http", action="store_true",
                     help="Fingerprinting HTTP")
    grp.add_argument("--waf", action="store_true",
                     help="Deteccao de WAF/CDN")
    grp.add_argument("--tech", action="store_true",
                     help="Identificacao de tecnologias")
    grp.add_argument("--headers", action="store_true",
                     help="Auditoria de headers de seguranca")
    grp.add_argument("--portas", action="store_true",
                     help="Varredura de portas TCP")
    grp.add_argument("--subdomains", action="store_true",
                     help="Brute-force de subdomains")
    grp.add_argument("--email", action="store_true",
                     help="Verificacao de seguranca de email (SPF/DKIM/DMARC)")
    grp.add_argument("--ct", action="store_true",
                     help="Certificate Transparency logs (crt.sh)")
    grp.add_argument("--asn", action="store_true",
                     help="Lookup ASN/BGP via ipinfo.io + bgpview.io")
    grp.add_argument("--s3", action="store_true",
                     help="Descoberta de S3/GCS/Azure buckets expostos")
    grp.add_argument("--cors", action="store_true",
                     help="Verificar CORS misconfiguration (Origin reflection)")
    grp.add_argument("--js", action="store_true",
                     help="Extrair endpoints de arquivos JS")
    grp.add_argument("--openredirect", action="store_true",
                     help="Testar open redirect em parametros comuns")
    grp.add_argument("--passivedns", action="store_true",
                     help="Passive DNS via HackerTarget (sem key) ou VirusTotal")

    # Opcoes de porta
    grp_port = parser.add_argument_group("Opcoes de varredura de portas")
    grp_port.add_argument("--portas-lista",
                          help="Lista de portas separadas por virgula (ex: '80,443,8080')")
    grp_port.add_argument("--portas-top50", action="store_true",
                          help="Varrer apenas as top 50 portas mais comuns")

    # Opcoes de subdomain
    grp_sub = parser.add_argument_group("Opcoes de subdomain")
    grp_sub.add_argument("--wordlist",
                         help="Arquivo de wordlist customizado para subdomains")

    # CT
    grp_ct = parser.add_argument_group("Opcoes de CT logs")
    grp_ct.add_argument("--ct-limite", type=int, default=200,
                        help="Maximo de certificados CT a analisar (padrao: 200)")

    # Geral
    grp_geral = parser.add_argument_group("Opcoes gerais")
    grp_geral.add_argument("--output", metavar="FILE",
                           help="Salvar resultados em arquivo JSON")
    grp_geral.add_argument("--threads", type=int, default=50,
                           help="Threads para port scan e subdomain enum (padrao: 50)")
    grp_geral.add_argument("--timeout", type=float, default=3.0,
                           help="Timeout em segundos por conexao (padrao: 3.0)")
    grp_geral.add_argument("--rate-limit", type=float, default=0,
                           help="Maximo de requisicoes/segundo HTTP (0=sem limite)")
    grp_geral.add_argument("--proxy",
                           help="Proxy HTTP/HTTPS/SOCKS5 (ex: http://127.0.0.1:8080)")
    grp_geral.add_argument("--stealth", action="store_true",
                           help="Modo furtivo: User-Agent aleatorio + delays")
    grp_geral.add_argument("--verbose", action="store_true",
                           help="Saida detalhada (debug)")
    grp_geral.add_argument("--shodan-key", metavar="KEY", default=None,
                           help="Shodan API key para lookup de host")
    grp_geral.add_argument("--vt-key", metavar="KEY", default=None,
                           help="VirusTotal API key para passive DNS")
    grp_geral.add_argument("--html-output", metavar="FILE", default=None,
                           help="Salvar relatorio HTML (ex: relatorio.html)")

    args = parser.parse_args()

    # Se nenhum modulo selecionado, mostrar ajuda rapida
    modulos = [args.dns, args.whois, args.ssl, args.http, args.waf, args.tech,
               args.headers, args.portas, args.subdomains, args.email, args.ct,
               args.asn, args.s3, args.cors, args.js, args.openredirect,
               args.passivedns, args.completo,
               bool(getattr(args, "shodan_key", None))]
    if not any(modulos):
        print(BANNER)
        print(f"\n{C['Y']}  [!] Nenhum modulo selecionado. Use --completo ou selecione modulos especificos.")
        print(f"  [!] Exemplo: python ghost-recon.py -d {args.dominio} --completo{C['X']}\n")
        parser.print_help()
        sys.exit(0)

    print(BANNER)
    print(f"  {C['C']}Alvo     : {C['N']}{args.dominio}{C['X']}")
    print(f"  {C['C']}Threads  : {C['N']}{args.threads}{C['X']}")
    print(f"  {C['C']}Timeout  : {C['N']}{args.timeout}s{C['X']}")
    print(f"  {C['C']}Stealth  : {C['N']}{'Sim' if args.stealth else 'Nao'}{C['X']}")
    if args.proxy:
        print(f"  {C['C']}Proxy    : {C['N']}{args.proxy}{C['X']}")
    print()

    # Desabilitar avisos SSL (requests)
    if REQUESTS_OK:
        import urllib3
        urllib3.disable_warnings()

    inicio = time.time()
    resultados = escanear(args.dominio, args)
    elapsed = time.time() - inicio

    print(f"\n  {C['G']}{C['N']}[+] Concluido em {elapsed:.1f}s{C['X']}")

    if args.output:
        gerar_relatorio(resultados, args.output, verbose=args.verbose)

    html_out = getattr(args, "html_output", None)
    if html_out:
        gerar_relatorio_html(resultados, html_out)


if __name__ == "__main__":
    main()
