# Ghost-Recon v1.0.0

**By Gh0st-Bx1 | [github.com/Ghost-Bx1](https://github.com/Ghost-Bx1)**

---

Framework de reconhecimento ofensivo completo para pentest e pesquisa de seguranca. Realiza enumeracao de DNS, SSL/TLS, HTTP fingerprinting, deteccao de WAF/CDN, identificacao de tecnologias, auditoria de headers, varredura de portas, brute-force de subdomains, verificacao de seguranca de email e consulta ao Certificate Transparency.

## Modulos

| Modulo | Descricao |
|--------|-----------|
| `--dns` | Enumeracao completa de registros DNS (A/AAAA/MX/NS/TXT/SOA/CAA) |
| `--whois` | Informacoes WHOIS do dominio |
| `--ssl` | Analise de certificado SSL/TLS (validade, emitente, SANs, grau) |
| `--http` | Fingerprinting HTTP (headers, servidor, redirecionamentos) |
| `--waf` | Deteccao de WAF/CDN (Cloudflare, AWS, Akamai, Imperva, etc.) |
| `--tech` | Identificacao de tecnologias (CMS, frameworks, linguagens) |
| `--headers` | Auditoria de headers de seguranca (HSTS, CSP, X-Frame, etc.) |
| `--portas` | Varredura de portas TCP com banner grabbing |
| `--subdomains` | Brute-force de subdomains com wordlist embutida ou customizada |
| `--email` | Verificacao de seguranca de email (SPF, DKIM, DMARC, MTA-STS) |
| `--ct` | Certificate Transparency logs via crt.sh |
| `--completo` | Executa todos os modulos acima |

## Uso

```bash
# Recon basico
python ghost-recon.py -d exemplo.com

# Todos os modulos
python ghost-recon.py -d exemplo.com --completo

# Selecionar modulos
python ghost-recon.py -d exemplo.com --dns --ssl --http --headers

# Brute-force de subdomains com 30 threads
python ghost-recon.py -d exemplo.com --subdomains --threads 30

# Wordlist customizada
python ghost-recon.py -d exemplo.com --subdomains --wordlist minha-lista.txt

# Varredura de portas
python ghost-recon.py -d exemplo.com --portas --portas-lista "80,443,8080,8443,3306"
python ghost-recon.py -d exemplo.com --portas --portas-top50

# Deteccao de WAF + tecnologias + headers
python ghost-recon.py -d exemplo.com --waf --tech --headers

# Verificacao de email
python ghost-recon.py -d exemplo.com --email

# Certificate Transparency (limite 200 entradas)
python ghost-recon.py -d exemplo.com --ct --ct-limite 200

# Stealth + proxy + saida JSON
python ghost-recon.py -d exemplo.com --completo --stealth --rate-limit 5 \
  --proxy http://127.0.0.1:8080 --output resultado.json

# Timeout personalizado + verbose
python ghost-recon.py -d exemplo.com --timeout 5 --verbose
```

## Opcoes Globais

| Opcao | Descricao |
|-------|-----------|
| `-d DOMINIO` | Alvo (dominio ou IP) |
| `--threads N` | Threads para brute-force (padrao: 20) |
| `--timeout N` | Timeout de conexao em segundos (padrao: 10) |
| `--proxy URL` | Proxy HTTP/HTTPS/SOCKS5 |
| `--rate-limit N` | Maximo N requisicoes/segundo |
| `--stealth` | Rotacao de User-Agent + delays aleatorios |
| `--output FILE` | Salvar resultado em JSON |
| `--verbose` | Saida detalhada |

## Dependencias

```bash
pip install requests

# Opcional - melhora resolucao DNS
pip install dnspython
```

## Aviso Legal

Esta ferramenta e destinada exclusivamente a pesquisa de seguranca e testes de penetracao autorizados. Use apenas em sistemas para os quais voce tem permissao explicita. O autor nao se responsabiliza pelo uso indevido.
