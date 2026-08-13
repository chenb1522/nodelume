# NodeLume v1.0.0 Test Report

The following checks were run against the v1.0.0 source before final packaging.

## Build / static validation

- `gofmt` completed.
- `go test ./...` passed.
- `go vet ./...` passed.
- `go test -race ./server ./agent` passed.
- JavaScript syntax (`node --check`) passed.
- HTML parser validation passed.
- All six shell scripts pass `sh -n`.
- Server and Agent `--version` / `--self-check` passed.
- Linux amd64 binaries were confirmed statically linked; final release also cross-builds static arm64 binaries.
- Agent source review confirms no remote shell / arbitrary command action; privileged command execution is fixed to explicitly coded operations.

## Live Server + Agent integration

A real local Server, low-level helper socket and Agent process were launched and exercised through HTTP APIs (loopback HTTP was enabled only for isolated testing):

- first administrator password setup and login passed;
- state-changing API without CSRF returned 403;
- custom administrator entry path passed; old `/` returned 404;
- trusted-proxy source IP handling passed;
- three failed logins returned 1/3, 2/3 and ban; the correct password remained blocked for that IP;
- Server restart cleared the in-memory IP ban;
- password change revoked the active session; old password failed and new password succeeded;
- node creation and one-time enrollment passed;
- Agent registration, independent Agent secret, heartbeat and online state passed;
- enrollment-token replay was rejected;
- remote non-loopback plain HTTP Agent configuration was rejected unless the explicit test override was supplied;
- CPU/memory/disk/system metrics and 5-second history were returned;
- disk detail API passed;
- an undefined `/api/exec` endpoint was not available;
- PID 1 was rejected;
- the running NodeLume Agent was detected as protected and termination was rejected;
- a disposable direct `sleep` process was inspected, SIGTERM-terminated through the fixed protocol, confirmed exited (including zombie/reap semantics), retained as a local recovery record and started again with a new PID;
- a second disposable direct process was restarted through `process_restart`, producing a new PID;
- recovery snapshots are persisted before destructive recoverable actions; if persistence fails the destructive action is refused;
- common secret-bearing command arguments and URL credentials are redacted from UI command lines and disable persistent direct-restart snapshots;
- audit records included node creation and process control operations.

## Agent update tests

- A signed v1.0.1 Agent test release was served from an isolated local release endpoint.
- Web `agent_upgrade` command installed the signed Agent, caused the old Agent to exit, retained `.previous` + pending state, then a simulated systemd restart launched v1.0.1.
- The first successful heartbeat to a Server speaking protocol v1 committed the update; pending state and previous binary were removed.
- A tampered Agent artifact with unchanged signed metadata was rejected in prior update-path validation.
- A correctly signed intentionally broken Agent whose `--self-check` passed but normal startup failed was installed as pending; the helper watchdog automatically restored v1.0.0 when no healthy reconnect committed the update.

## Server update tests

- A correctly signed v1.0.1 Server replacement updated v1.0.0 successfully and passed HTTP `/healthz` validation.
- A correctly signed intentionally non-starting Server replacement passed its synthetic self-check but failed startup; the updater restored v1.0.0 and `/healthz` returned healthy again.
- Update status recorded `success` or `rolled_back` as appropriate.

## Release bootstrap verification

- First-install trust is pinned by the public Ed25519 key embedded in the installer.
- Installer verification uses OpenSSL Ed25519 verification on `checksums.txt` before executing the downloaded NodeLume binary, then checks the binary SHA-256 and NodeLume self-check.
- This avoids trusting a newly downloaded binary to establish its own first-install trust.

## Not falsely claimed as locally end-to-end tested

- A real public ACME certificate issuance/renewal was not possible in the isolated build environment because it requires a real DNS name and inbound public ports 80/443. ACME directory/order/challenge/certificate persistence and renewal paths are implemented, but the final public-CA challenge must be smoke-tested on the deployment domain.
- The supplied systemd installers were not boot-tested on separate real Debian, Ubuntu, CentOS Stream, AlmaLinux and Rocky Linux VMs in this container environment. The runtime collector avoids distro-specific tools, and the final release contains static amd64/arm64 binaries, but production smoke testing on one representative VPS is recommended before rolling out broadly.
- The build environment's Chromium policy blocked loopback browser navigation, so the final split Web assets were syntax/DOM validated rather than falsely claiming a new automated browser run. The responsive interaction design itself is the user-approved UI iteration carried into these assets.
