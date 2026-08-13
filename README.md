# NodeLume v1.0.0

**NodeLume — See Every Node Clearly**

NodeLume is a lightweight multi-node Linux server monitor built around three priorities: **low resource usage, quick deployment, and security before feature count**.

## Architecture

- `nodelume-server`: static Go binary, embedded Web UI, multi-node management, in-memory history.
- `nodelume-agent`: static Go binary, outbound-only communication; remote non-loopback Server URLs require HTTPS by default.
- Agent runs as the low-privilege `nodelume-agent` user.
- Privileged actions use a local Unix socket and a **systemd socket-activated root helper**. The helper has no network listener and is not a remote shell.
- No `sh -c`, `bash -c`, arbitrary `exec`, arbitrary command string, terminal, script or custom-command protocol exists in the Agent.
- Server and Agent share protocol version `1`; release versions are independent from protocol compatibility.

## Monitoring

- CPU, memory, filesystem usage, load average, network throughput and temperature when the host exposes sensors.
- CPU / memory top processes and full process list.
- Process source detection: systemd service/child, direct/manual binary, cron, container, background process, kernel thread or unknown.
- Process detail: executable path, working directory, sanitized command line, parent and process tree.
- Common password/token/authorization arguments and URL credentials are redacted from displayed command lines.
- `/proc/<pid>/environ` is deliberately **never uploaded or displayed**.
- Metric history is a fixed `720` point ring per node, sampled every 5 seconds: maximum **1 hour**.
- Chart ranges: **1 / 5 / 10 / 30 / 60 minutes**, with normal time and percentage axes.

## Process control security

The Server can request only fixed Agent actions. Unknown actions are rejected.

Read/diagnostic actions include system/process/disk/network/sensor information. Privileged actions are limited to fixed operations such as:

- `process_terminate` → SIGTERM
- `process_kill` → SIGKILL, only as an explicit second-step force action
- `process_restart`
- `process_start_saved`
- `service_stop`
- `service_restart`
- `agent_upgrade`

PID 1, NodeLume itself, SSH, systemd core services, network/firewall services, Docker/containerd and other protected targets are denied.

For a directly started binary, NodeLume saves only a root-owned local restart snapshot (`exe`, `argv`, `cwd`, `uid`, `gid`) before a destructive action. The snapshot is not uploaded to the Server and environment variables are not copied. If command arguments appear to contain passwords, tokens, Authorization headers, API keys or URL credentials, direct restart/recovery is intentionally disabled so those secrets are not persisted. If a safe recovery record cannot be persisted, the recoverable stop/restart action is refused.

## Web security

- First visit initializes the administrator password; only a salted PBKDF2-HMAC-SHA256 derived hash is stored.
- Three failed logins from the same effective source IP ban that IP until the Server process restarts.
- Login-ban state is memory-only; audit records remain persistent.
- Session cookie is `HttpOnly` + `SameSite=Strict`; it is `Secure` when NodeLume can verify HTTPS.
- State-changing Web APIs require a per-session CSRF token.
- Custom administrator entry path; after changing it, the old Web entry returns 404.
- Trusted reverse-proxy CIDRs are opt-in. `X-Forwarded-For` / `X-Forwarded-Proto` are ignored unless the immediate peer is trusted.
- Security headers include CSP, frame denial, `nosniff`, no-referrer and restrictive permissions policy.
- Each node has its own random Agent secret; Server storage contains only the secret hash.
- Enrollment tokens are single-use and expire after 30 minutes.
- A non-loopback Agent enrollment URL must use HTTPS. Plain remote HTTP is rejected unless the explicit testing-only override is used.

## HTTPS

The Web settings support two deployment models:

1. **Reverse proxy** — keep NodeLume on `127.0.0.1:8080` and terminate HTTPS with Nginx/Caddy/etc.
2. **Built-in ACME** — NodeLume binds 80/443, performs HTTP-01, stores the certificate under `/var/lib/nodelume/acme`, serves HTTPS and periodically checks renewal.

Built-in ACME requires the configured domain to resolve to the Server and public TCP port 80 to reach NodeLume. Do not enable it when another service already owns 80/443.

## Linux support

The collector reads Linux `/proc`, `/sys` and syscalls instead of depending on `top`, `free`, `df`, Python, Node.js or a distro package manager.

The supplied service installers target **systemd** Linux distributions, including modern Debian, Ubuntu, CentOS Stream, AlmaLinux and Rocky Linux. Release binaries are built for Linux `amd64` and `arm64` with `CGO_ENABLED=0`.

For secure first installation the shell installer requires an OpenSSL build with Ed25519 verification support. NodeLume intentionally refuses an unverified first binary.

## Repository layout

```text
.github/workflows/release.yml
agent/
server/
  web/
scripts/
  install-server.sh
  update-server.sh
  uninstall-server.sh
  install-agent.sh
  update-agent.sh
  uninstall-agent.sh
tools/
  keygen/
  sign/
go.mod
release.pub
```

## Release signing key — important

This v1.0.0 handoff uses the public trust anchor committed in `release.pub`. The matching private signing key is delivered **separately from the source/release archives**.

Before creating the first GitHub tag, add the exact private-key value to the repository Actions secret:

```text
NODELUME_SIGNING_PRIVATE_KEY
```

Then delete your local private-key handoff file after storing it securely. **Never commit the private key.**

`go run ./tools/keygen --apply .` exists only for creating a completely new trust root **before any NodeLume release or installation has been deployed**. Do not casually rotate the key after deployment: existing Servers and Agents intentionally reject releases signed by an unknown key.

## GitHub release

Push a semantic version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

`.github/workflows/release.yml` then:

1. runs Go tests;
2. builds Server + Agent for Linux amd64/arm64;
3. generates `release-manifest.json`;
4. generates SHA-256 checksums;
5. signs the checksum file with Ed25519;
6. publishes all release assets to GitHub Releases.

## Install Server

After the GitHub Release exists, latest stable installation is one command:

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/install-server.sh | sh
```

Pinned v1.0.0 installation:

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/v1.0.0/scripts/install-server.sh | sh -s -- --version v1.0.0
```

Default internal listener:

```text
127.0.0.1:8080
```

Open the Web page through HTTPS/reverse proxy, or first access the local/internal endpoint as appropriate, then create the administrator password.

## Add Agent

In the Web UI choose **添加服务器**. NodeLume creates a 30-minute one-time enrollment command that pins the Agent to the current compatible Server release. Paste it into the target VPS as root.

After installation:

- the normal Agent runs low privilege;
- the privileged helper is systemd socket-activated only when required;
- the VPS does not open an Agent monitoring port.

## Updates

Server CLI update:

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/update-server.sh | sh
```

Agent CLI update:

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/update-agent.sh | sh
```

Both accept `--version vX.Y.Z` for a pinned upgrade/rollback target.

The Web UI can check GitHub Releases, queue a Server update, update one Agent or update Agents sequentially.

Update transaction:

```text
download temporary file
→ verify signed checksums + SHA-256
→ new binary self-check
→ preserve current binary
→ replace
→ restart / reconnect
→ health + protocol check
→ commit
```

If startup, reconnect, protocol validation or health check fails, the previous binary is restored automatically. The Web/CLI reports the failure/rollback state.

## Uninstall

Keep configuration/data by default:

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/uninstall-server.sh | sh
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/uninstall-agent.sh | sh
```

Full removal:

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/uninstall-server.sh | sh -s -- --purge
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/main/scripts/uninstall-agent.sh | sh -s -- --purge
```

Server and Agent may be co-installed on the same machine. Purge scripts preserve the shared release trust anchor when the other NodeLume component is still installed.

## Intentional limits

- Metric history disappears after Server restart because the one-hour history is intentionally RAM-only.
- Direct/manual process restart is best effort. Applications that require secret environment configuration should normally be managed/restarted by their service manager instead.
- Container and protected critical processes are not directly restarted.
- NodeLume intentionally favors refusing an unsafe operation over providing a broader remote-control feature.
