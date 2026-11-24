# Restricted Nmap scanner on the existing Azure VM

The `remote-nmap-web-ports-v1` profile performs unprivileged TCP connect discovery on **only ports 80 and 443**, on **one approved public IPv4 address**. It uses the existing VM and Windows application, job queue, permission checks, reports, analyst reviews and Findings dashboard. It is port reachability testing, not a comprehensive vulnerability scan.

## Authorisation and use

Existing web/header permissions are insufficient. Before requesting this profile:

1. Obtain written authority covering TCP port discovery on both ports and the underlying server IP. Domain ownership alone does not establish authority over shared hosting/CDN infrastructure.
2. Register a current authorisation containing both the exact hostname and the explicitly approved public IPv4 address in `authorized_domains`. The schema already accepts hostnames and IPs; no database migration is needed.
3. Include **both** `automated_non_intrusive_scanning` and `tcp_port_discovery` in `permitted_methods`. Upload/inspect the genuine permission evidence, accept its current evidence review and approve the authorisation through the existing workflow. Do not edit or reuse a web-only approval as if it granted this permission.
4. Select **Nmap · restricted TCP ports 80 and 443** in Assessments, choose this approval, enter the note and confirm the explicit request and TCP permission checkboxes.
5. Run the existing assessment worker. Results show each port as open, closed or filtered, scanner CPU/peak memory, container duration, the pinned IP and cleanup status. Use analyst review to evaluate expected exposure; nothing becomes a confirmed finding automatically.

The trusted Windows DNS-only broker rejects any unsafe DNS answer, including mixed public/private records. A public IPv4 address must be present in both the fresh DNS result and reviewed authorisation scope. IPv6-only targets or DNS rotation to an unapproved IP fail closed. DNS resolution does not connect to the target; all target TCP connections occur inside Docker on the VM. No local Nmap fallback exists.

An example permission scope is an array containing your owned hostname and its approved numeric public IPv4 address. Resolve the address using your normal DNS tools, verify ownership/authority, and transcribe it from the written scope. Do not use placeholder, private, loopback or metadata IPs. The existing authenticated API documentation at `/docs` exposes the authorisation schema, including the new `tcp_port_discovery` method. An existing approved record is never automatically amended.

## Fixed command and isolation

The scanner uses `-sT -Pn -n --unprivileged --disable-arp-ping -p 80,443`, one outstanding probe, a 500 ms scan delay, zero Nmap retries, one-second response timeouts and a five-second host timeout. There is no service/version probing, OS detection, NSE scripting, UDP, host discovery, custom ports, templates or arbitrary command input. See the official [TCP connect scan documentation](https://nmap.org/book/man-port-scanning-techniques.html) and [timing controls](https://nmap.org/book/man-performance.html). Short timeouts can misclassify delayed/filtered services; open ports alone are not vulnerabilities.

Each execution creates two randomly named, labelled containers from the approved immutable image:

- **Scanner:** UID/GID 65532, read-only filesystem, all capabilities dropped, no-new-privileges, 128 MiB memory/no extra swap, 0.5 CPU, 16 PIDs, bounded file descriptors, no core dumps, Docker logs disabled and no restart. Python/Nmap have independent deadlines. The XML contract accepts only the expected IP and ports, with bounded output; raw XML and guessed service labels are not persisted.
- **Network policy helper:** root with **only NET_ADMIN** inside its own bridge-connected container network namespace. This is trusted policy code, not the scanner. It installs default-DROP IPv4/IPv6 policies, permitting outbound TCP only to the pinned IPv4 on ports 80/443 and related replies. It has no listeners, published ports, Docker socket, bind mounts, host networking or privileged-container mode. Its root filesystem is read-only, with a 64 KiB noexec/nosuid `/run` tmpfs for the firewall lock. Limits: 64 MiB memory, 0.1 CPU, 16 PIDs and an independent 35-second alarm.

The scanner joins only the helper's network namespace and has no capability to change its firewall. No host network namespace, host directory or credentials are shared. This is stronger than validating DNS and giving Nmap an unrestricted bridge. Docker's capability and network namespace options are documented in [Running containers](https://docs.docker.com/engine/containers/run/).

The helper must report policy readiness before the scanner is created. The runner then asks Windows for a fresh permission decision immediately before launching Nmap. Revocation, cancellation, image changes, expired evidence/approval or the worker lease prevent result acceptance. An already-sent TCP probe cannot be undone. All network profiles share the existing one-active-job pool, one attempt, no automatic retry and 60-second per-website cooldown.

## SSH and lifecycle

The adapter invokes only `/usr/local/libexec/snwebshield-nmap-runner`, `--check` and `--cleanup <generated_hex_id>`. Targets are bounded JSON stdin, never shell commands or Docker arguments. SSH uses the existing OS configuration/key, BatchMode and strict host verification. Private keys remain outside the repository, application environment and containers.

Preflight is bounded to eight seconds, the DNS broker to five, remote execution to 32 and targeted cleanup to eight. Nmap itself is bounded to eight seconds under a ten-second entry alarm; Docker attach is bounded to 12. Cancellation/termination invokes targeted cleanup of scanner first, then helper, checking both labels/role and approved image ID. No pre-existing container, image, volume or data is deleted. If connectivity or the daemon fails, cleanup remains unconfirmed; inspect only the exact scanner execution ID before any approved manual deletion. No broad prune is implemented. Process/VM crashes can leave stopped orphans despite independent process deadlines.

Reports bind image ID, approved destination and ports, configured limits, Nmap child-process CPU time/peak RSS, scanner/container/runner durations and cleanup. CPU/peak RSS are process measurements rather than whole-container peaks and exclude the Python wrapper and helper; their container resource limits remain enforced. Port observations use `tcp_port_80` and `tcp_port_443` and support the same analyst decisions, reviewed JSON snapshots, retest checks and central Findings tracking. A header-only retest cannot resolve a TCP finding because it does not contain the required port observation.

## Installed image and configuration

The scanner is built from the existing cached Python base `python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`, using signed Debian packages. Installed versions are recorded in `/usr/local/share/snwebshield-package-versions`: Nmap `7.95+dfsg-3`, iptables `1.8.11-2`. The approved runtime image is pinned to:

```text
sha256:a37d1d80fd260c867f67ca1c3150ab4b8a30c2bc337722574951b9470e9008a9
```

Runtime always uses this immutable ID with `--pull=never`, not a mutable tag. Rebuilding/updating packages is an administrator action requiring review, a new image pin and repeat acceptance; it does not occur per job. The build uses the cached Python base; later source fixes reused the cached package layer. Previous images and the header-analysis configuration were preserved. No Azure resources, registries, public Docker TCP port, new host service or full-application deployment were created.

Root-owned VM files:

- `/usr/local/libexec/snwebshield-nmap-runner`
- `/usr/local/lib/snwebshield/nmap_policy.py`
- `/etc/snwebshield/nmap-image-id`

Default example configuration is disabled. The private Windows backend settings require:

```dotenv
ASSESSMENT_NMAP_ENABLED=true
ASSESSMENT_NMAP_IMAGE_ID=sha256:a37d1d80fd260c867f67ca1c3150ab4b8a30c2bc337722574951b9470e9008a9
```

Restart the API/worker after settings change. Existing header profiles are unchanged. No schema migration or modification to current authorisations is required for installing this profile.

## Repeatable validation

From `backend`, `python -m app.cli.nmap_check` performs an explicit infrastructure self-test against the existing VM's own public IP on the two fixed ports. It accepts no target arguments, creates no client assessment job, and does not test any registered website. It is a real TCP self-test, not a network-free test.

The administrator-only `scanner/nmap/verify_host.py` runs on the VM and checks the same self target, rejects unsafe inputs, inspects configuration and uses fixed diagnostics inside the scanner boundary. It verifies blocked extra ports, other destinations, private/metadata addresses, loopback/DNS and IPv6 policy, plus kernel drop counters, UID/capabilities, read-only storage, inability to manage the firewall, pre-scan permission denial, timeout, cancellation and targeted cleanup. Test programs do not extend the production runner's accepted command protocol.

No client website/IP was port-scanned during development. Only the already-designated scanner VM was a permitted live test target; forbidden-destination attempts were blocked inside the container namespace. Synthetic API/browser fixtures never contact real targets. Keep using the [existing VM deallocation guidance](REMOTE_DOCKER_SCANNER.md#azure-costs-and-shutdown) when the VM is unused.

Validated on 2026-11-24: all 299 backend tests, 14 frontend helper tests, 18 browser scenarios and the production build passed, plus the live VM isolation suite and Windows self-test. The self-test reported the VM's own ports 80/443 closed, container duration 1356.438 ms, Nmap CPU 0.028979 seconds, Nmap peak RSS 16,736,256 bytes and confirmed cleanup. Docker's equivalent `NET_ADMIN`/`CAP_NET_ADMIN` names are normalised by the test assertion without changing privileges. The final VM container listing contained only the original three stopped hello-world containers; no Docker TCP listener was present. Runner/policy/image configuration files are root-owned. The private Windows Nmap settings are enabled and pinned; restart running API/workers to load them. Distributed example settings remain disabled, and no actual client assessment was queued or authorisation altered.
