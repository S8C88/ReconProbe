# ReconProbe — Engineering Report

## Overview

**Project:** ReconProbe
**Version:** 1.1
**Author:** Sideways 8 Security Research
**Category:** Reconnaissance / Enumeration

ReconProbe is a multi-phase reconnaissance tool that combines passive and active techniques for subdomain discovery and port scanning. Built for HTB/VulnHub box enumeration, bug bounty scope mapping, and internal network assessments where you need fast results without spinning up a full toolchain.

---

## Tech Stack

### Language: Python 3.10+

Chosen for rapid prototyping, wide library support, and cross-platform availability. No compilation step, works on any box with Python. Performance isn't critical here — the bottlenecks are network I/O, not CPU.

### Networking: `socket` stdlib

Zero dependency for core port scanning. `connect_ex` with timeouts gives us TCP state detection without raw sockets (no root required). This means it runs on standard pentest boxes without privilege escalation.

### HTTP: `requests`

Used for crt.sh API calls and banner grabbing. It's the de facto standard for HTTP in Python. Could use `urllib` but `requests` is more readable and handles edge cases better (timeouts, SSL, redirects).

### Parallelism: `concurrent.futures.ThreadPoolExecutor`

Thread-based parallelism for I/O-bound operations (DNS resolution, port scanning). Python's GIL doesn't matter here — we're waiting on network, not CPU. Max 50 workers by default, adjustable. No async complexity.

---

## Architecture Decisions

### Why not use nmap?

Nmap is the gold standard for port scanning, but:
1. Needs to be installed on the target system
2. Output parsing is its own problem
3. We wanted lightweight banner grabbing without NSE scripts
4. Having a pure-Python scanner means easy customization mid-engagement

ReconProbe's scanner is intentionally basic — SYN scan requires raw sockets (root), so we use TCP connect scan instead. It's slower and more detectable but works without privileges.

### Why crt.sh for passive recon?

Certificate Transparency logs are the easiest passive source for subdomains. No API key needed, no rate limiting for small queries, and it catches a lot of subdomains that DNS brute-force misses. crt.sh surfaces subdomains issued by any CA, so wildcard certs and SAN entries are fair game.

The tradeoff: crt.sh data is not real-time. Certs can lag days behind deployment. We pair it with DNS brute-force to catch subdomains that aren't in CT logs.

### Thread pool sizing

Default 50 workers. Empirical testing shows diminishing returns past 50 for DNS resolution — the local resolver becomes the bottleneck. For port scanning, 100 workers works well since the bottleneck is remote host response time.

---

## File Structure

```
ReconProbe/
├── reconprobe.py          # Main tool
├── README.md              # Usage + UML docs
├── LICENSE                # MIT
├── requirements.txt       # requests only
└── tests/
    └── test_reconprobe.py # 100-pass test suite
```

---

## Testing Strategy

Test suite runs 19 distinct test cases covering:
- Domain validation (normal + edge cases)
- DNS resolution (success + failure)
- Batch resolution
- Port scanning (localhost + known ports)
- Output generation (CSV, JSON, terminal)
- Error handling (timeout, unreachable, malformed input)
- Data structure integrity (COMMON_PORTS, SRT_QUERIES)

Each test run executes all 19 cases. The 100-pass runner shuffles the execution order each iteration using a seeded random to catch order-dependent failures. First 5 failures are printed; after that only pass/fail counts are shown.

---

## Security Considerations

- No raw sockets — requires no special privileges
- No packet injection — fully passive scanning
- Banner grabbing only sends benign probes (HTTP HEAD, newline)
- Output files don't contain sensitive data beyond what the user targets
- Input validation prevents command injection via domain names
- No external code execution (no shell=True, no eval, no exec)

---

## Known Limitations

1. **No UDP scanning** — TCP only. SCTP, UDP, and IP protocols not covered.
2. **TCP connect scan** — Less stealthy than SYN scan, logged by target systems.
3. **No service fingerprinting** — Banner grab is best-effort. No regex-based service identification.
4. **Single-resolver bottleneck** — No multi-resolver support, no DNS-over-HTTPS.
5. **crt.sh rate limits** — No built-in backoff for aggressive queries.
6. **No CIDR/range scanning** — Only hostname-based targeting.
