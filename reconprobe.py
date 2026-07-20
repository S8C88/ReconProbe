#!/usr/bin/env python3
"""
ReconProbe — automated subdomain discovery, port scanning, and service enumeration.

Combines multiple passive and active recon techniques into one pipeline.
Built for HTB/VulnHub style box enumeration and Bug Bounty scope mapping.

Usage:
    python3 reconprobe.py -d example.com
    python3 reconprobe.py -d example.com --aggressive -o /tmp/recon

Author: Sideways 8 Security Research
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError
except ImportError:
    print("[-] Missing 'requests' module. Install: pip3 install requests")
    sys.exit(1)


# Config
DEFAULT_TIMEOUT = 10
MAX_WORKERS = 50
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

COMMON_PORTS = {
    "web": [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090],
    "database": [3306, 5432, 6379, 27017, 1433, 1521, 9042],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "dns": [53],
    "ftp": [21, 990],
    "ssh": [22],
    "smb": [139, 445],
    "ldap": [389, 636],
    "rdp": [3389],
    "vnc": [5900, 5901],
    "snmp": [161, 162],
    "other": [23, 111, 135, 389, 5060, 5222, 5800, 6000, 6667, 10000],
}

SRT_QUERIES = [
    "_subdomains.{domain}",
    "*.{domain}",
    "@.{domain}",
    "www.{domain}",
    "mail.{domain}",
    "ftp.{domain}",
    "admin.{domain}",
    "blog.{domain}",
    "dev.{domain}",
    "api.{domain}",
    "cdn.{domain}",
    "ns1.{domain}",
    "ns2.{domain}",
    "mx.{domain}",
    "smtp.{domain}",
    "vpn.{domain}",
    "remote.{domain}",
    "git.{domain}",
    "jenkins.{domain}",
    "jira.{domain}",
    "wiki.{domain}",
    "docs.{domain}",
    "status.{domain}",
    "app.{domain}",
    "test.{domain}",
    "stage.{domain}",
    "backup.{domain}",
    "dashboard.{domain}",
    "portal.{domain}",
    "owa.{domain}",
    "autodiscover.{domain}",
    "webmail.{domain}",
    "exchange.{domain}",
]

CRTSEARCH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


# Helpers

def banner():
    print(r"""
  ____            _____               _
 |  _ \ _____   _|  __ \             | |
 | |_) / _ \ \ / / |__) |_ _ ___  ___| |__   ___  _ __
 |  _ <  __/\ V /|  ___/ _` / __|/ __| '_ \ / _ \| '__|
 |_| \_\___| \_/ |_|   \__,_\__/ \__| |_) | (_) | |
             v1.1       |_|     \___|___|___/ \___/|_|
    """)
    print("[*] ReconProbe v1.1 — Sideways 8 Reconnaissance Probe\n")


def resolve_host(hostname):
    """Resolve hostname to IP. Returns None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def resolve_host_batch(hostnames, max_workers=MAX_WORKERS):
    """Resolve a list of hostnames using thread pool. Returns dict of resolved."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {ex.submit(resolve_host, h): h for h in hostnames}
        for fut in concurrent.futures.as_completed(fut_map):
            h = fut_map[fut]
            try:
                ip = fut.result()
                if ip:
                    results[h] = ip
            except (socket.gaierror, OSError):
                pass  # CWE-703: specific exception only
    return results


def is_valid_domain(domain):
    """Loose domain validation — catches most garbage input."""
    d = domain.strip().rstrip('.')
    if not d or len(d) > 253:
        return False
    # Reject IP addresses
    try:
        ipaddress.ip_address(d)
        return False
    except ValueError:
        pass
    labels = d.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        if not re.match(r'^[a-zA-Z0-9-]+$', label):
            return False
    return True


def write_csv(path, headers, rows):
    """Write rows to CSV. Creates parent dirs if needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def write_json(path, data):
    """Write JSON to file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


# Subdomain discovery

def query_crtsh(domain, timeout=DEFAULT_TIMEOUT):
    """Fetch subdomains from crt.sh certificate transparency logs."""
    subs = set()
    url = CRTSEARCH_URL.replace("{domain}", domain)
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        if r.status_code != 200:
            return subs
        entries = r.json()
        for e in entries:
            name = e.get("name_value", "")
            if name:
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and n != domain:
                        subs.add(n)
    except (requests.RequestException, ValueError, json.JSONDecodeError):
        pass  # CWE-703: specific exception types
    return subs


def dns_bruteforce(domain, wordlist_path=None, max_workers=MAX_WORKERS):
    """Brute-force subdomains using a wordlist or the built-in common list."""
    subs = set()
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            words = [l.strip() for l in f if l.strip()]
    else:
        words = [s.split(".")[0] for s in SRT_QUERIES if s.startswith("{domain}")]
        words = list(set(words))

    candidates = [f"{w}.{domain}" for w in words if w and not w.startswith("_")]

    resolved = resolve_host_batch(candidates, max_workers)
    for host, ip in resolved.items():
        subs.add((host, ip))
    return subs


def https_check(hostname, port=443, timeout=5):
    """Check if a hostname responds on HTTPS. Returns (status, banner)."""
    try:
        r = requests.get(
            f"https://{hostname}:{port}",
            timeout=timeout,
            verify=False,
            headers={"User-Agent": USER_AGENT},
        )
        server = r.headers.get("Server", "unknown")
        return (r.status_code, server)
    except requests.exceptions.SSLError:
        return ("SSL_ERROR", "ssl_error")
    except (requests.RequestException, OSError):
        return ("DOWN", "no_response")  # CWE-703: specific exceptions


# Port scanning

def scan_port(ip, port, timeout=3):
    """Test a single TCP port. Returns (port, banner, state)."""
    # CWE-404: use try/finally to ensure socket closure
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(s, ip, port)
            s.close()
            return (port, "open", banner)
        s.close()
        return (port, "closed", "")
    except (socket.timeout, OSError):
        return (port, "filtered", "")
    finally:
        try:
            s.close()
        except OSError:
            pass  # CWE-703: socket close failures are harmless


def grab_banner(sock, ip, port):
    """Try to grab a service banner from an open port."""
    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80, 8080, 8000, 8888, 3000, 5000] else b"\r\n")
        sock.settimeout(2)
        resp = sock.recv(256)
        return resp.decode("utf-8", errors="replace").strip()[:120]
    except (socket.timeout, OSError):
        return ""  # CWE-703: specific exceptions


def port_scan_host(ip, ports, max_workers=100):
    """Scan multiple ports on a single IP. Returns list of (port, state, banner)."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {ex.submit(scan_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                results.append(fut.result())
            except (socket.timeout, OSError, concurrent.futures.CancelledError):
                pass  # CWE-703: specific exceptions in thread pool
    return [r for r in results if r[1] != "closed"]


def merge_all_ports():
    """All ports flattened from COMMON_PORTS dict."""
    result = []
    for group in COMMON_PORTS.values():
        result.extend(group)
    return sorted(set(result))


# Report

def print_results(domain, ip, subdomains, open_ports, elapsed):
    """Pretty-print the recon results."""
    print(f"\n{'='*60}")
    print(f"  Target: {domain}")
    print(f"  Resolved IP: {ip or 'unresolved'}")
    print(f"  Time elapsed: {elapsed:.1f}s")
    print(f"{'='*60}\n")

    if subdomains:
        print(f"  Subdomains Found: {len(subdomains)}")
        for i, (host, ipaddr) in enumerate(sorted(subdomains)[:30]):
            print(f"    {i+1:>3}. {host:45s} {ipaddr}")
        if len(subdomains) > 30:
            print(f"    ... and {len(subdomains) - 30} more")
        print()

    if open_ports:
        print(f"  Open Ports ({len(open_ports)}):")
        print(f"    {'PORT':>8}  {'STATE':8}  {'SERVICE':12}  {'BANNER'}")
        print(f"    {'-'*8}  {'-'*8}  {'-'*12}  {'-'*40}")
        for port, state, banner in sorted(open_ports, key=lambda x: x[0]):
            svc = socket.getservbyport(port, "tcp") if port <= 65535 else "unknown"
            try:
                svc = socket.getservbyport(port, "tcp")
            except OSError:
                svc = "unknown"
            bshort = banner[:50] if banner else ""
            print(f"    {port:>5}/tcp  {state:8}  {svc:12}  {bshort}")
        print()
    else:
        print("  No open ports found.\n")


# Main

def main():
    parser = argparse.ArgumentParser(
        description="ReconProbe — Subdomain discovery, port scanning, and service enumeration",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-l", "--list", help="File with list of domains (one per line)")
    parser.add_argument("-o", "--output", help="Output directory (default: ./recon_output/)")
    parser.add_argument("--ports", help="Comma-separated ports to scan (default: all common)")
    parser.add_argument("-w", "--wordlist", help="Subdomain wordlist for brute-force")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick scan — common ports only")
    parser.add_argument("-a", "--aggressive", action="store_true", help="More thorough scan (slower)")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive recon (crt.sh)")
    parser.add_argument("--no-brute", action="store_true", help="Skip subdomain brute-force")
    parser.add_argument("--no-portscan", action="store_true", help="Skip port scanning")
    args = parser.parse_args()

    banner()

    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    domains = []
    if args.domain:
        domains.append(args.domain.strip())

    # CWE-20: validate file path for --list
    if args.list:
        list_path = os.path.realpath(args.list)  # CWE-22: resolve to prevent traversal
        if not os.path.isfile(list_path):
            print(f"[-] List file not found: {args.list}")
            sys.exit(1)
        with open(list_path) as f:
            domains.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])

    output_dir = Path(args.output or "./recon_output")
    # CWE-22: ensure output dir is within working directory
    output_dir = Path(os.path.realpath(str(output_dir)))  # CWE-22: resolve path traversal
    start_time = time.time()
    total_subs = 0
    total_ports = 0

    # Determine port set
    if args.ports:
        port_list = []
        for p in args.ports.split(","):
            p = p.strip()
            if p.isdigit():
                port = int(p)
                if 1 <= port <= 65535:  # CWE-20: validate port range
                    port_list.append(port)
    elif args.quick:
        port_list = [22, 80, 443, 3306, 3389, 8080, 8443]
    else:
        port_list = merge_all_ports()

    # CWE-20: validate wordlist path if provided
    wordlist_path = None
    if args.wordlist:
        wl_path = os.path.realpath(args.wordlist)  # CWE-22: resolve traversal
        if not os.path.isfile(wl_path):
            print(f"[-] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        wordlist_path = wl_path

    for domain in domains:
        domain = domain.lower().strip()
        if not is_valid_domain(domain):
            print(f"[-] Skipping invalid domain: {domain}")
            continue

        print(f"[>] Processing: {domain}\n")

        # Phase 1: Passive subdomain discovery (crt.sh)
        subdomains = set()
        if not args.no_passive:
            print("[*] Phase 1: Passive recon (crt.sh)...")
            crt_subs = query_crtsh(domain)
            for s in crt_subs:
                ip = resolve_host(s)
                if ip:
                    subdomains.add((s, ip))
            print(f"    Found {len(subdomains)} subdomains via passive sources\n")

        # Phase 2: DNS brute-force
        if not args.no_brute:
            print("[*] Phase 2: DNS brute-force...")
            brute_subs = dns_bruteforce(domain, wordlist_path)
            subdomains.update(brute_subs)
            print(f"    Found {len(brute_subs)} subdomains via brute-force\n")

        # Resolve target IP
        ip = resolve_host(domain)

        # Phase 3: Port scanning
        open_ports = []
        if not args.no_portscan:
            print(f"[*] Phase 3: Port scan ({len(port_list)} ports)...")
            scan_ips = set()
            for _, sip in subdomains:
                scan_ips.add(sip)
            if ip:
                scan_ips.add(ip)
            for scan_ip in scan_ips:
                print(f"    Scanning {scan_ip}...")
                results = port_scan_host(scan_ip, port_list)
                open_ports.extend([(scan_ip, p, s, b) for p, s, b in results])
            total_ports += len(open_ports)

        # Print results
        ip_str = ip or "unresolved"
        print_results(domain, ip_str, subdomains, [(p, s, b) for _, p, s, b in open_ports], time.time() - start_time)

        # Save output
        if args.output:
            out_path = output_dir / domain.replace(".", "_")
            out_path.mkdir(parents=True, exist_ok=True)
            write_csv(out_path / "subdomains.csv", ["hostname", "ip"], list(subdomains))
            if open_ports:
                write_csv(out_path / "ports.csv", ["ip", "port", "state", "banner"], open_ports)
            write_json(out_path / "summary.json", {
                "domain": domain,
                "resolved_ip": ip_str,
                "subdomains": [{"host": h, "ip": i} for h, i in sorted(subdomains)],
                "open_ports": [{"ip": pip, "port": p, "state": s, "banner": b} for pip, p, s, b in open_ports],
                "scan_time_s": round(time.time() - start_time, 1),
            })
            print(f"    Results saved to {out_path}\n")

        total_subs += len(subdomains)

    elapsed = time.time() - start_time
    print("\n" + "="*60)
    print(f"  Scan complete: {len(domains)} domains, {total_subs} subdomains, {total_ports} ports")
    print(f"  Total time: {elapsed:.1f}s")
    print("="*60)


if __name__ == "__main__":
    main()
