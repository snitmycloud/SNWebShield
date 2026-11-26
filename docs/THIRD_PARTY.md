# Third-party data, services and software

What SNWebShield uses that it did not write, under which terms, and what is sent where. Updated for every phase that adds one. Nothing here is fetched by a scan except where it says "at scan time".

## Data and services used in Phase 3A

| Source | What we use | Where it is used | Terms | What is sent |
|---|---|---|---|---|
| **NVD**, the US National Vulnerability Database (NIST), `services.nvd.nist.gov` | CVE records matched to a product and version (description, CVSS score and vector, affected version ranges) | At scan time, through `app/services/vuln_sources.py`, cached for 24 hours in `vuln_cache` | NVD data is public-domain US government data. The NVD API terms ask for an API key for higher rates, attribution ("This product uses data from the NVD API but is not endorsed or certified by the NVD") and no abuse of the rate limit; we stay at 5 requests per 30 s without a key and 50 with one | Only a software **name and version** as a CPE name (for example `cpe:2.3:a:openbsd:openssh:6.6.1:p1:...`), never a domain, IP address, user or scan id. The optional `NVD_API_KEY` is sent only in the `apiKey` header and is never logged |
| **OSV**, Open Source Vulnerabilities (Google), `api.osv.dev` | Advisories for JavaScript libraries (npm: jQuery, Bootstrap, React, AngularJS/Angular, Vue, Lodash, Moment) | At scan time, same layer and cache | OSV's API is free to use; the advisories come from their sources and are mostly CC-BY 4.0 (GitHub Advisory Database) and similar open licences, which require attribution (given here) | Only a package **name, ecosystem and version** |
| **endoflife.date** | Release and end-of-support dates for Ubuntu, Debian, CentOS, RHEL, PHP, nginx, Apache, MySQL, MariaDB, WordPress, Tomcat and others | **Not at scan time.** A developer runs `backend/tools/update_eol.py` and commits the generated `app/data/eol.json` | The project's source is MIT-licensed (checked 2026-11-25); the site does not state a separate licence for its data, so we treat the data as covered by the same MIT terms and keep this notice: *endoflife.date, Copyright (c) endoflife.date contributors, MIT License.* If the licence is ever clarified differently, the file will be regenerated or removed | Nothing (a developer tool; it sends only fixed product names) |
| **crt.sh** (Sectigo), certificate-transparency search | List of subdomain names from public certificates | At scan time (Phase 2) | Public certificate-transparency data; used politely (one request per scan, 6 s timeout) | Only the **domain name** being scanned (public information, needed to look it up) |
| **Nmap `nmap-services`** | The 1,000 most frequent TCP port numbers and port-to-service names (`app/data/top_ports.py`, `app/data/ports.py`) | Generated once by `tools/make_top_ports.py`; the app never downloads it | Nmap Public Source License (NPSL). We use only facts (port numbers, frequencies and names), not Nmap code, and we do not redistribute the Nmap file itself | Nothing |

We do **not** use Wikipedia text (CC BY-SA) or any other source with share-alike terms.

## Python and JavaScript packages

Backend: only the standard library plus the packages already listed in `backend/requirements.txt` (including `dnspython`, ISC licence, pinned). Phase 3A added **no new package**. Frontend: React, lucide-react (ISC) and Vite (MIT), unchanged.

## Planned for Phase 3B (not in 3A, nothing of it is installed)

| Item | Licence | Note |
|---|---|---|
| **Nuclei** (ProjectDiscovery) engine | MIT | Will be pinned to an exact version and checked against the official release checksum before use |
| **nuclei-templates** (ProjectDiscovery) | MIT | A reviewed subset only, vendored with its licence file and validated before every use |

## Updating this file

Any change that adds a data source, a package or a service updates this table in the same commit, with the licence and what is sent.
