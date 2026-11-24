# Existing Azure VM: remote header analysis

The React app, FastAPI API, assessment worker, SQLite database, evidence and reports stay on Windows. Only selected response headers and status/TLS metadata travel to the existing `azureuser@57.159.27.58` VM. No new Azure resources, registry, deployment, Docker TCP listener, background service or automatic image pull is involved.

## Inspection and current status

The user's supplied read-only output reports Ubuntu 24.04.5 LTS, Docker client/server 29.10.0, two CPUs, 15.56 GiB total memory, approximately 14 GiB available and 24 GB free root disk. The three pre-existing stopped hello-world containers remain intact. This is sufficient capacity for one limited header analyser. The application and database remain on Windows.

User-operated VM setup built and installed the analyser and runner. The approved analyser image ID is `sha256:3eb5d06053b254da7dbd5aa0bd2149326e3ead250a9e1234e4d95144e35fffd2`. Runner/config ownership and permissions were confirmed as root:root, 755/644. Windows SSH now authenticates using a dedicated scanner key outside the repository; its public entry disables forwarding, PTY and user RC via `restrict`. The old passphrase-protected key is preserved. No private key was copied or put in application settings.

Live acceptance passed: synthetic analysis, unselected-header rejection, UID 65532, only loopback networking, blocked outbound connection, kernel-enforced read-only root, inspected CPU/memory/PID/capability configuration, timeout with cleanup and SIGTERM cancellation with cleanup. The actual Windows bounded subprocess/SSH interface also passed with zero target requests: container duration 423.213 ms, analyser CPU 0.10685 seconds, peak RSS 13,983,744 bytes and cleanup confirmed. The final Docker listing contained only the original three hello-world containers. A genuinely authorised target HEAD and analyst review remain user acceptance steps; no website was contacted during these checks.

The existing private Windows backend .env now enables remote Docker assessments with this immutable image ID and keeps the local HTTP profile disabled. Restart any running API/assessment worker to load these settings. The default example configuration remains disabled. No target job was queued automatically.

Windows compatibility fix: the SSH subprocess receives a whitelist of OS profile paths/identity names so Windows OpenSSH can initialise and locate its OS-managed configuration. Application secrets remain excluded. The trusted local Python broker keeps its original smaller environment. Windows Job Object process/memory/CPU limits remain enforced; no unbounded fallback was added.

## Execution contract

`remote-docker-headers-v1` is a distinct, default-off profile. The existing local profile remains available only under its separate opt-in; the remote profile never falls back to it. Requests bind the immutable image ID into their execution snapshot. An image-pin change, revocation, expiry, evidence change, altered scope or disabled profile prevents queued execution/result acceptance.

1. Check current administrator, client/website relationship, approved authorisation, dates, exact domain, permitted scanning method, audited human approval and current accepted, integrity-checked evidence. Require explicit request and separate network permission confirmation.
2. Over OS-managed SSH, call only `/usr/local/libexec/snwebshield-header-runner --check`. Confirm the runner version, local approved image ID and Docker access before any target HEAD. SSH uses BatchMode, strict known-host verification and bounded connection time. No keys, passwords, Docker options or commands are accepted through the API.
3. The trusted local broker checks all DNS answers, rejects private/special/mixed destinations, pins one public IP and checks the connected peer. HTTPS validates certificates/SNI. Send one HEAD, without retries, GET fallback or response-body reads. Reject all redirect traversal, including unsafe destinations, by following no redirects. A 3xx response can itself be analysed; its Location is never sent to Azure.
4. Send only eight selected header names, HTTP status and verified-HTTPS boolean as bounded JSON stdin. No URL, target identity, evidence, cookies, authorisation documents, credentials or database data reaches the container. Header values exist transiently in memory, not persisted in reports or Docker logs.
5. The fixed VM runner uses `/usr/bin/docker` with an immutable `sha256:` image ID from a root-controlled file. It creates a randomly named, labelled container with `--pull=never`, `--network=none`, UID/GID 65532, read-only filesystem, all capabilities dropped, no-new-privileges, 64 MiB memory/no extra swap, 0.25 CPU, 16 PIDs, bounded file descriptors, disabled core dumps, no restart and disabled Docker logs. There are no host mounts, published ports or writable tmpfs.
6. The analyser returns only fixed-schema human-review observations for CSP, HSTS, framing, nosniff, referrer/permissions policies and disclosure. The backend checks the exact analysis contract. It never marks these as confirmed vulnerabilities.
7. Record private reports, provenance, audit events and usage. Usage includes analyser CPU time and peak RSS (not whole-container peak memory), analyser duration, container lifetime from Docker timestamps, runner execution duration excluding cleanup, image ID and configured limits. Failed/cancelled/disconnected runs may have unavailable usage; do not invent zeros. The dashboard shows successful usage and cleanup; audit events retain cleanup uncertainty even when cancellation discards the result.

Limits: one global assessment slot, one outstanding assessment per website, one attempt, no automatic security-operation retry and a shared 60-second cooldown across HTTP profiles. The local broker has a 13-second parent deadline and independent 12-second watchdog. SSH phases have 10-second preflight, 22-second execution and 10-second cleanup deadlines. Docker start/attach has an independent 8-second timeout; the analyser has a 5-second alarm. Other Docker commands are separately bounded. Cancellation polls live permission, terminates the local SSH process and requests removal of only the broker-generated execution ID. The remote runner also removes its container in `finally`, independently of the Windows connection. An already-sent HEAD cannot be undone.

If SSH fails, no local-analysis fallback occurs. If SSH disconnects after container creation, cleanup is **unconfirmed** until the VM is inspected: a concurrent targeted cleanup request is not proof the original runner has finished. The runner's normal bounded lifecycle removes containers, but VM/runner crashes or a hung Docker daemon can leave an orphan. There is no broad prune or deletion sweep.

The SSH identity has Docker access, which is effectively host-administrator access with a rootful daemon. Protect the Windows account, SSH agent and VM runner. Networkless Docker isolation does not make arbitrary images trusted; review the small fixed source and base image. Docker controls are documented in the [official run reference](https://docs.docker.com/reference/cli/docker/container/run/).

## Milestone 1 hardening (2026-11-24)

- **SSH transport.** `backend/app/services/ssh_transport.py` is the only place SSH argv is built. It uses `%SystemRoot%\System32\OpenSSH\ssh.exe` (or `/usr/bin/ssh`) instead of a `PATH` lookup, and these command-line options override `~/.ssh/config`: `BatchMode=yes`, `StrictHostKeyChecking=yes`, `UpdateHostKeys=no`, `PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`, `ForwardAgent=no`, `ForwardX11=no`, `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `ProxyCommand=none`, `ProxyJump=none`, `ControlMaster=no`, `ControlPath=none` and `RequestTTY=no`. The `IdentityFile` from your config is still used. The options were checked with `ssh -G` on Windows OpenSSH 9.5, and `app.cli.scanner_check` passed live through this transport.
- **Fail closed.** A missing client gives `ssh_client_unavailable`. An unreachable VM gives `adapter_exited_without_result`. Docker or image problems give `remote_preflight_failed`. Each is recorded on the job and in the `remote_docker_execution_finished` event. No target HEAD is sent after a failed preflight.
- **Per-run isolation inspection (requires runner redeploy).** After `docker container create`, the runner inspects the container. It refuses to start it unless the image, owner label, `NetworkMode=none`, UID 65532, read-only rootfs, non-privileged mode, `CapDrop=ALL` with no `CapAdd`, no-new-privileges, 64 MiB memory/swap, 0.25 CPU, 16 PIDs, `IpcMode=none`, no mounts/binds/ports/devices and no restart policy all match. It reports `isolation_verified: true`, which the backend stores as `isolation_attested`. Runners installed before this change report `isolation_attested: false`. Once the new runner is installed, set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true` so runs without an attestation fail.

### Redeploying the Milestone 1 runner (manual)

The VM steps are manual because they need `sudo`. No image rebuild is needed: the analyser image and `container_entry.py` are unchanged, so `ASSESSMENT_REMOTE_IMAGE_ID` stays the same.

```powershell
# From the Windows repository root: copy only the runner and verifier.
scp scanner/remote_runner.py scanner/verify_host.py azureuser@57.159.27.58:snwebshield-scanner/scanner/
```

```bash
# On the VM: review the diff against the installed copy, then install.
diff /usr/local/libexec/snwebshield-header-runner ~/snwebshield-scanner/scanner/remote_runner.py
sudo install -o root -g root -m 755 ~/snwebshield-scanner/scanner/remote_runner.py /usr/local/libexec/snwebshield-header-runner
/usr/local/libexec/snwebshield-header-runner --check
/usr/bin/python3 -I ~/snwebshield-scanner/scanner/verify_host.py
```

Then on Windows, run `.\.venv\Scripts\python.exe -m app.cli.scanner_check` from `backend` and expect `"isolation_attested": true`. Set `ASSESSMENT_REMOTE_REQUIRE_ISOLATION_ATTESTATION=true` in the private `.env` and restart the API and assessment worker.

## Manual VM setup (user-operated; not executed by this change)

First finish key authentication from the Windows account that runs the backend. Keep private keys outside the repository, application environment and containers; use the OS SSH agent/config. Verify the VM's host fingerprint through a trusted channel before populating known_hosts. Never disable host checking or enable port 2375. Test from Windows:

```powershell
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes azureuser@57.159.27.58 "true"
```

Review the four existing images using `docker image ls --no-trunc`. Reuse an appropriate existing Python base if its provenance is known; otherwise intentionally obtain a reviewed official Python 3 slim image by digest. Do not blindly use an existing unrelated application image, floating `latest` tag or repeat pulls/builds on every job. Resolve and record a reviewed digest before building. The following commands are examples for the user to run on the existing VM, from a copy of **only** the analyser sources and scanner build files with the repository directory layout. Do not copy `.env`, databases, evidence, the full application or keys. The Dockerfile-specific ignore file excludes unrelated build context.

```bash
# Substitute a real reviewed digest; this placeholder must not be run literally.
docker build --pull=false -f scanner/Dockerfile \
  --build-arg PYTHON_BASE=python:3.12-slim@sha256:REPLACE_WITH_REVIEWED_DIGEST \
  -t snwebshield-header-analysis:v1 .
docker image inspect --format '{{.Id}}' snwebshield-header-analysis:v1
```

Install the runner and write the resulting immutable image ID. These create only SNWebShield-specific files; review existing destination files before replacing any previous installation:

```bash
sudo install -d -m 755 /usr/local/libexec /etc/snwebshield
sudo install -o root -g root -m 755 scanner/remote_runner.py /usr/local/libexec/snwebshield-header-runner
# Substitute the actual sha256 image ID printed above (not its tag/base digest).
printf '%s\n' 'sha256:REPLACE_WITH_ANALYSIS_IMAGE_ID' | sudo tee /etc/snwebshield/header-image-id >/dev/null
sudo chmod 644 /etc/snwebshield/header-image-id
/usr/local/libexec/snwebshield-header-runner --check
```

On Windows, keep `ASSESSMENT_LOCAL_HTTP_ENABLED=false`; add to the existing private backend `.env`:

```dotenv
ASSESSMENT_REMOTE_DOCKER_ENABLED=true
ASSESSMENT_REMOTE_IMAGE_ID=sha256:REPLACE_WITH_ANALYSIS_IMAGE_ID
```

Do not put SSH key material or a private-key path in application settings. Restart API and worker after configuration changes. No additional database migration is introduced; the pre-existing `0006_local_http` migration supplies execution snapshots/reports. Back up the local database/evidence privately before applying any pending migration. Do not run a downgrade.

With genuine written permission for your own controlled test site, choose the Azure profile in Assessments and confirm both permissions. Run the Windows worker from `backend`:

```powershell
.\.venv\Scripts\python.exe -m app.cli.operations assessment-worker --once
```

Verify one HEAD/no redirected requests in the owned server's access logs; inspect the private report, usage and events. No real target was contacted during development tests.

## Validation and repeatable acceptance

Local Windows validation on 2026-11-23: 242 backend tests passed (one Starlette/httpx deprecation warning), 12 frontend helper tests passed, 14 Chromium browser journeys passed and the Vite production build passed. The 23 remote-specific backend tests use simulated SSH/Docker. Browser fixtures also simulate the remote host; no Azure or target network access occurred. The final browser run exited cleanly outside the sandbox after a sandboxed run required explicit test-helper cleanup. A monitoring browser assertion was corrected to retry both overview and history because their separate requests can straddle a job commit. Git whitespace checks, scanner syntax and Linux runner LF line endings were verified.

An administrator-only acceptance script, `scanner/verify_host.py`, automates synthetic analysis, rejection of unselected headers, kernel UID/read-only/network checks, Docker resource/security configuration checks, the eight-second timeout and SIGTERM cancellation with targeted cleanup. It uses only the approved image and randomly named test containers. It does not extend the production runner protocol, contact targets, pull/build images or remove pre-existing containers. After SSH authentication is fixed, copy only this script and run it on the existing VM:

```powershell
# From the Windows repository root:
scp scanner/verify_host.py azureuser@57.159.27.58:snwebshield-scanner/scanner/verify_host.py
ssh azureuser@57.159.27.58 /usr/bin/python3 -I /home/azureuser/snwebshield-scanner/scanner/verify_host.py
```

Then verify the actual Windows application subprocess/SSH protocol from `backend`, without enabling assessments or contacting a target:

```powershell
.\.venv\Scripts\python.exe -m app.cli.scanner_check
```

Expect `passed: true`, `target_requests: 0` and confirmed cleanup. This command uses the configured immutable image ID. Only after live acceptance succeeds, enable `ASSESSMENT_REMOTE_DOCKER_ENABLED=true` and restart the API/assessment worker. An actual target HEAD still requires a separately queued assessment with genuine accepted written authorisation.

Local tests simulate SSH/Docker success, denial, timeout, cancellation, output validation and cleanup ownership. They check the fixed isolation flags; they do **not** prove kernel-enforced isolation. On the VM, use a dedicated manually created test container from the approved image with the same flags and inspect `HostConfig`, `Config.User`, `Mounts` and `NetworkSettings`. Verify there is no non-loopback network interface, outbound connection is unavailable, writing to `/app` fails and UID is 65532. Do not modify the production analyser to accept arbitrary diagnostic commands through the API.

Exercise a test-owned sleeping container to verify deadline/cancellation removal, then a successful job. Compare `docker container ls -a --filter label=com.snwebshield.runner` before/after, preserving the existing three containers. Test expired/revoked/evidence-changed/method-denied requests without target access. Until these pass, keep remote execution disabled. If cleanup is unconfirmed, inspect the exact `snws-headers-<execution_id>` and label/image; approve any manual orphan deletion explicitly. Never run `docker system prune`, image/volume pruning or removal of unrelated containers.

## Azure costs and shutdown

No additional Azure service is needed. VM compute charges continue while the existing VM is allocated, even when no containers run. In Azure Portal, open the **existing** VM, choose **Stop**, and verify its status becomes **Stopped (deallocated)**. A shutdown inside Ubuntu can leave compute allocated. OS/data disks, reserved public IPs and other attached resources can continue to incur charges after deallocation. Do not delete them. Deallocation may change a dynamic public IP on restart; verify the address before resuming jobs. See [Microsoft VM states and billing](https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing). Before stopping, finish/cancel assessments and verify no SNWebShield execution is active. No automated stop/deallocate or Azure account actions are implemented.
