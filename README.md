# WHOIS Support Dashboard

Internal support tool for checking:
- WHOIS domain
- Full DNS records
- IP / ASN / Network provider
- Smart alerts for support

## Features
- RDAP WHOIS (when available)
- DNS records: A, AAAA, NS, MX, TXT, CNAME
- IP → ASN / ISP (INET, VNPT, Viettel, Cloudflare, AWS…)
- Alert engine for support use

## Tech Stack
- Node.js + Express
- Google DNS
- RDAP
- ipinfo.io

## Run backend
```bash
cd backend
npm install
node server.js
