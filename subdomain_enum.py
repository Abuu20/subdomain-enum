#!/usr/bin/env python3
"""
Subdomain / Recon Enumerator
Author: AbuBakar Issa Sabalah

Enumerates likely subdomains of a target domain using DNS resolution
against a wordlist. Useful for authorized reconnaissance during
penetration tests and attack-surface mapping.

USE RESPONSIBLY: Only enumerate domains you own or have explicit
written permission to test.
"""

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "test", "staging", "api", "app", "admin", "portal",
    "vpn", "remote", "cpanel", "blog", "shop", "store", "m",
    "mobile", "secure", "cdn", "static", "media", "images",
    "support", "help", "docs", "status", "git", "gitlab", "jenkins",
]


def resolve(subdomain: str, domain: str):
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return None


def enumerate_subdomains(domain: str, wordlist, max_threads: int = 50):
    print(f"\nEnumerating subdomains for: {domain}")
    print(f"Wordlist size: {len(wordlist)}\n")

    found = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(resolve, word, domain): word for word in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                fqdn, ip = result
                print(f"  [FOUND] {fqdn:<35} -> {ip}")
                found.append((fqdn, ip))

    print(f"\nEnumeration complete. {len(found)} subdomain(s) resolved.")
    return found


def load_wordlist(path: str):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    parser = argparse.ArgumentParser(description="Subdomain Recon Enumerator")
    parser.add_argument("domain", help="Target root domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Max concurrent threads")
    args = parser.parse_args()

    wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_WORDLIST
    enumerate_subdomains(args.domain, wordlist, args.threads)


if __name__ == "__main__":
    main()
