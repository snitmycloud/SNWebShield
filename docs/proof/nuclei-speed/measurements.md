# Nuclei speed: what was measured (2026-11-26/27, Windows development host)

## Why only 160 requests in 4 min 38 s

Measured with the real Nuclei v3.11.1 and the egress proxy, against a **fast local server** (so the target's speed cannot be the cause):

| Setup (30 s run, 3,948 templates) | Requests | Requests per second |
|---|---|---|
| Egress proxy alone, 50 parallel requests | 50 in 0.05 s | handles connections in parallel; closes each at once (**not the cause**) |
| Default flags (`-rl 25 -c 10`) | 60 | **2.0** |
| `-timeout 2` | 60 | 2.0 (so a slow response is not the cause) |
| `-nmhe -dc` (no host-error skip, no clustering) | 60 | 2.0 |
| `-c 50` | 300 | 10.0 (throughput = concurrency / 5 s, a fixed ~5 s wait per template) |
| **`-r <loopback-only resolver file> -sr`** | **658** | **21.9** (the 25/s rate limit) |

**Cause:** Nuclei does its own DNS look-ups. The firewall rule that blocks `nuclei.exe`'s direct network access (the second safety layer) also blocks those look-ups, and each one waited about 5 seconds before giving up. **Fix:** a resolver file that names only `127.0.0.1` (fails at once) plus `-sr`, which falls back to the operating system's resolver for a plain name look-up. Nuclei still never connects to the target itself; the egress proxy is unchanged. Request timeout lowered from 10 s to 5 s, retries stay 0.

## Quick vs Deep

* **Quick** (normal scans, 1,426 templates + CVE templates for detected software, capped at 300): all exposures (466), all misconfiguration (814), the 146 sensitive panels, and CVE templates whose tags or product match software we detected.
* **Deep** (all 3,948; only for scheduled deep scans, Phase 5, Pro and above): not reachable from the app yet.

## Real scan of scanme.nmap.org with Quick (demo admin, Nuclei on, worker started with `NUCLEI_ENABLED=true`)

* Nuclei step: **99.4 s**, 1,435 templates, **1,778 requests** (about 18 per second), exit code 0.
* Whole scan: 146 s (ports 18 s, DNS step 17 s, Nuclei about 100 s).
* Proxy log: 1,778 allowed (all `scanme.nmap.org:80`, **IP 45.33.32.156 only**) and 2 refused (`port_not_allowed`, ports 9001 and 4040: templates for other ports, correctly blocked).
* Findings from Nuclei: "HTTP Missing Security Headers" (Info). It overlaps the built-in header checks, which stay as they are.
* The scan ended "incomplete" because the DNS step could not check DMARC once (a resolver hiccup 17 s long; a direct look-up a minute later took 0.3 s). That is unrelated to Nuclei.

## Parallel Nuclei, Nuclei on by default (2026-11-27)

* Nuclei Quick now starts together with the vulnerability and end-of-life steps (limit 180 s). On scanme the NVD cache was warm, so those steps took 6 s and Nuclei set the pace: Nuclei **105 s**, **1,778 requests**, whole scan **150 s (2 min 30 s)**, status **completed**.
* Proxy log (`parallel-scan-proxy-log.jsonl`): 1,778 allowed, all `scanme.nmap.org:80` at **45.33.32.156**; 2 refused (`port_not_allowed`).
* Nuclei's start-up self-test took 132 s because two shutdowns waited for a hung test connection (`EgressProxy.stop()` and the canary server); fixed, now 16 s.
* The scan ended "completed" because every core step finished: the DNS step passed, and the configuration step's single CORS request is now retried once. The subdomain list (optional) could not be fetched, which does not matter.
