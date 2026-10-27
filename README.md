# Ghost-Recon

> By Gh0st-Bx1 | [github.com/Ghost-Bx1](https://github.com/Ghost-Bx1)

Framework de reconhecimento ofensivo completo para pentest e pesquisa de seguranca. Realiza enumeracao abrangente de um alvo em um unico comando.

---

## Funcionalidades

| Modulo | Descricao |
|---|---|
| `--dns` | Registros A, AAAA, MX, NS, TXT, SOA, CAA + deteccao de zone transfer |
| `--whois` | Informacoes WHOIS (registrar, datas, status, NS) |
| `--ssl` | Certificado SSL/TLS: validade, emitente, SANs, protocolo, cipher |
| `--http` | Fingerprinting HTTP: status, server, headers, redirecionamentos |
| `--waf` | Deteccao de 13+ WAF/CDN (Cloudflare, AWS WAF, Akamai, Imperva, F5...) |
| `--tech` | Identificacao de 25+ tecnologias (CMS, frameworks, linguagens, servidores) |
| `--headers` | Auditoria de headers de seguranca (HSTS, CSP, X-Frame-Options, etc.) |
| `--portas` | Varredura TCP com banner grabbing (60+ portas comuns) |
| `--subdomains` | Brute-force DNS com wordlist embutida (150+ entradas) ou customizada |
| `--email` | SPF, DKIM (14 seletores), DMARC, MTA-STS com score de seguranca |
| `--ct` | Certificate Transparency logs via crt.sh |
| `--completo` | Executa todos os modulos acima |

---

## Instalacao

```bash
pip install requests
pip install dnspython  # opcional - melhora resolucao DNS
```

Python 3.7+ sem dependencias obrigatorias alem de `requests`.

---

## Uso

```bash
# Reconhecimento rapido (HTTP + WAF + tech + headers)
python ghost-recon.py -d exemplo.com --http --waf --tech --headers

# Analise completa
python ghost-recon.py -d exemplo.com --completo

# Enumeracao DNS + SSL
python ghost-recon.py -d exemplo.com --dns --ssl

# Brute-force de subdomains (threads agressivo)
python ghost-recon.py -d exemplo.com --subdomains --threads 50

# Brute-force com wordlist customizada
python ghost-recon.py -d exemplo.com --subdomains --wordlist /path/lista.txt

# Varredura de portas padrao
python ghost-recon.py -d exemplo.com --portas

# Portas especificas
python ghost-recon.py -d exemplo.com --portas --portas-lista "22,80,443,3306,6379"

# Seguranca de email
python ghost-recon.py -d exemplo.com --email

# CT logs (ate 200 certificados)
python ghost-recon.py -d exemplo.com --ct --ct-limite 200

# Completo + output JSON
python ghost-recon.py -d exemplo.com --completo --output resultado.json

# Modo furtivo com proxy
python ghost-recon.py -d exemplo.com --completo --stealth --proxy http://127.0.0.1:8080

# Verbose com rate limiting
python ghost-recon.py -d exemplo.com --completo --verbose --rate-limit 5
```

---

## Saida exemplo

```
   _____ _               _     ____
  / ____| |             | |   |  _ \
 | |  __| |__   ___  ___| |_  | |_) | ___  ___ ___  _ __
 ...

  [=] DNS RECON
  [+]   A      -> 104.21.14.105, 172.67.138.40
  [+]   MX     -> aspmx.l.google.com, alt1.aspmx.l.google.com
  [+]   NS     -> ns1.cloudflare.com, ns2.cloudflare.com

  [=] WAF/CDN
  [>] WAF/CDN detectado: Cloudflare (score=5)

  [=] EMAIL SECURITY
  [+] SPF: "v=spf1 include:_spf.google.com -all"
  [!] DMARC p=none - somente monitoramento
  Score email security: 2/4 - REGULAR
```

---

## Opcoes completas

```
opcoes:
  -d DOMINIO            Dominio ou IP alvo
  --completo            Executar todos os modulos
  --dns                 Enumeracao DNS
  --whois               Consulta WHOIS
  --ssl                 Analise SSL/TLS
  --http                Fingerprinting HTTP
  --waf                 Deteccao de WAF/CDN
  --tech                Identificacao de tecnologias
  --headers             Auditoria de headers de seguranca
  --portas              Varredura de portas TCP
  --subdomains          Brute-force de subdomains
  --email               Verificacao SPF/DKIM/DMARC
  --ct                  Certificate Transparency logs
  --portas-lista LISTA  Portas separadas por virgula
  --portas-top50        Apenas top 50 portas
  --wordlist FILE       Wordlist customizada para subdomains
  --ct-limite N         Max certificados CT (padrao: 200)
  --output FILE         Salvar resultados em JSON
  --threads N           Threads (padrao: 50)
  --timeout N           Timeout por conexao em segundos (padrao: 3.0)
  --rate-limit N        Max requisicoes HTTP/segundo
  --proxy URL           Proxy HTTP/HTTPS/SOCKS5
  --stealth             User-Agent aleatorio
  --verbose             Saida detalhada
```

---

## Aviso Legal

Uso exclusivo para pesquisa de seguranca, pentest autorizado e fins educacionais. O uso nao autorizado contra sistemas de terceiros e ilegal. Os autores nao se responsabilizam pelo uso indevido.
