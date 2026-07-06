# Subdomain / Recon Enumerator

A multithreaded DNS-based subdomain enumeration tool for authorized
reconnaissance and attack-surface mapping during security assessments.

## Features
- Fast concurrent DNS resolution
- Built-in wordlist of common subdomains, or bring your own
- Simple, readable output of resolved subdomains and their IPs

## Usage
```bash
python3 subdomain_enum.py example.com
python3 subdomain_enum.py example.com -w my_wordlist.txt -t 100
```

## Requirements
- Python 3.8+, standard library only

## Disclaimer
Only enumerate domains you own or have explicit written permission to
test. Unauthorized reconnaissance may violate computer misuse laws.

## Author
AbuBakar Issa Sabalah — Cybersecurity Analyst
