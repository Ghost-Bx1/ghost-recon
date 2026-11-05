# Ghost-Recon

> Offensive reconnaissance framework - DNS, WHOIS, SSL, HTTP, WAF, port scanning, subdomain enumeration, and email security in one command.

```
  GHOST-RECON  v1.0.0  |  Offensive Reconnaissance Framework
  By Gh0st-Bx1         |  github.com/Ghost-Bx1
```

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reconnaissance-blue?style=flat-square)

---

## Overview

Ghost-Recon runs a comprehensive passive and active reconnaissance sweep against a domain or IP. All modules can be run individually or combined with `--completo` for a full profile of the target.

| Module        | Description                                                              |
|---------------|--------------------------------------------------------------------------|
| `--dns`       | A, AAAA, MX, NS, TXT, SOA, CAA records + zone transfer detection        |
| `--whois`     | Registrar, creation date, expiry, status, nameservers                    |
| `--ssl`       | Certificate validity, issuer, SANs, protocol version, cipher suite       |
| `--http`      | HTTP fingerprinting: status, server header, redirects                    |
| `--waf`       | WAF/CDN detection: Cloudflare, AWS WAF, Akamai, Imperva, F5 and 8 more  |
| `--tech`      | Technology identification: CMS, frameworks, languages, web servers (25+) |
| `--headers`   | Security header audit: HSTS, CSP, X-Frame-Options and more              |
| `--portas`    | TCP port scan with banner grabbing (60+ common ports)                   |
| `--subdomains`| DNS brute-force with 150+ built-in entries or custom wordlist            |
| `--email`     | SPF, DKIM (14 selectors), DMARC, MTA-STS with security score            |
| `--ct`        | Certificate transparency logs via crt.sh                                 |
| `--completo`  | Run all modules                                                          |

---

## Requirements

```
Python 3.7+
requests        (required)
dnspython       (optional - improves DNS resolution)
```

```bash
pip install requests
pip install dnspython  # optional
```

---

## Installation

```bash
git clone https://github.com/Ghost-Bx1/ghost-recon
cd ghost-recon
pip install requests
```

---

## Usage

```bash
# Quick recon (HTTP + WAF + tech + headers)
python ghost-recon.py -d example.com --http --waf --tech --headers

# Full sweep
python ghost-recon.py -d example.com --completo

# DNS and SSL only
python ghost-recon.py -d example.com --dns --ssl

# Subdomain brute-force (aggressive thread count)
python ghost-recon.py -d example.com --subdomains --threads 50

# Subdomain brute-force with custom wordlist
python ghost-recon.py -d example.com --subdomains --wordlist /path/list.txt

# Port scan (default ports)
python ghost-recon.py -d example.com --portas

# Port scan - specific ports
python ghost-recon.py -d example.com --portas --portas-lista "22,80,443,3306,6379"

# Email security check (SPF/DKIM/DMARC)
python ghost-recon.py -d example.com --email

# Certificate transparency (up to 200 certs)
python ghost-recon.py -d example.com --ct --ct-limite 200

# Full sweep with JSON output
python ghost-recon.py -d example.com --completo --output result.json

# Stealth mode with proxy
python ghost-recon.py -d example.com --completo --stealth --proxy http://127.0.0.1:8080

# Verbose with rate limiting
python ghost-recon.py -d example.com --completo --verbose --rate-limit 5
```

---

## Reference

| Flag                | Description                                          |
|---------------------|------------------------------------------------------|
| `-d DOMAIN`         | Target domain or IP                                  |
| `--completo`        | Run all modules                                      |
| `--dns`             | DNS enumeration                                      |
| `--whois`           | WHOIS lookup                                         |
| `--ssl`             | SSL/TLS certificate analysis                         |
| `--http`            | HTTP fingerprinting                                  |
| `--waf`             | WAF/CDN detection                                    |
| `--tech`            | Technology identification                            |
| `--headers`         | Security header audit                                |
| `--portas`          | TCP port scan                                        |
| `--subdomains`      | Subdomain brute-force                                |
| `--email`           | SPF/DKIM/DMARC verification                          |
| `--ct`              | Certificate transparency logs                        |
| `--portas-lista`    | Comma-separated port list                            |
| `--portas-top50`    | Top 50 ports only                                    |
| `--wordlist FILE`   | Custom wordlist for subdomain brute-force            |
| `--ct-limite N`     | Max CT certificates to retrieve (default: 200)       |
| `--output FILE`     | Save results to JSON                                 |
| `--threads N`       | Thread count (default: 50)                           |
| `--timeout N`       | Per-connection timeout in seconds (default: 3.0)     |
| `--rate-limit N`    | Max HTTP requests per second                         |
| `--proxy URL`       | HTTP/HTTPS/SOCKS5 proxy                              |
| `--stealth`         | Randomize User-Agent                                 |
| `--verbose`         | Verbose output                                       |

---

## Roadmap

Improvements planned based on analysis of amass, subfinder, httpx and nuclei:

| Priority | Feature | Description |
|----------|---------|-------------|
| High | JavaScript file analysis | Extract API endpoints, secrets, tokens from inline and linked JS files found during HTTP scan |
| High | Shodan InternetDB enrichment | For each discovered IP, pull open ports, CVEs and tags without an API key |
| High | Wayback Machine URL harvest | Extract historical endpoints via CDX API; reveals old paths, forgotten admin panels |
| High | Subdomain takeover detection | CNAME chain check on all discovered subdomains for unclaimed services (S3, GitHub Pages, Heroku, Shopify) |
| High | API spec discovery | Check for `swagger.json`, `openapi.yaml`, `.well-known/api/`, `api-docs`, `/graphql` on discovered hosts |
| High | Favicon hash fingerprinting | Compute MurmurHash3 of target favicon for Shodan-style technology correlation |
| Medium | Cloud asset discovery | Generate bucket name permutations for target and probe S3/GCS/Azure Blob HEAD requests |
| Medium | Google Analytics ID correlation | Extract GA/GTM IDs from pages; find other domains using the same ID |
| Medium | Email harvesting from web pages | Regex scrape of `mailto:` links and email patterns in discovered pages |
| Medium | Autonomous crawler | Follow internal links up to configurable depth (`--crawl-depth 2`) to expand attack surface |
| Medium | Screenshot capture | Invoke `chromium --headless` or `cutycapt` on discovered HTTP services (`--screenshot`) |
| Low | Mobile app lookup | Check iOS App Store / Google Play for apps belonging to target domain |
| Low | Reverse DNS on discovered IPs | PTR lookup on every found IP to uncover sibling domains hosted on same infrastructure |
| Low | BGP/routing analysis | Enumerate all CIDR blocks registered to target ASN for expanded scope |

## Disclaimer

For use in authorized environments only. Penetration testing, CTF competitions, and offensive security research with explicit permission from the environment owner. The author is not responsible for misuse.

---

**By [Gh0st-Bx1](https://github.com/Ghost-Bx1)**
