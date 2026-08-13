#!/bin/sh
set -eu
REPO="chenb1522/nodelume"; VERSION=""; LISTEN="127.0.0.1:8080"; PUBLIC_URL=""; LOCAL_DIR=""
RELEASE_PUB="HuKgHCbJ3RDisYmD0u0sI0Jj86cQJJa7KVzDKvNAK4U="
while [ $# -gt 0 ]; do case "$1" in --repo) REPO="$2";shift 2;; --version) VERSION="$2";shift 2;; --listen) LISTEN="$2";shift 2;; --public-url) PUBLIC_URL="$2";shift 2;; --local-dir) LOCAL_DIR="$2";shift 2;; *) echo "Unknown argument: $1" >&2;exit 2;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "NodeLume Server requires systemd." >&2; exit 1; }
ARCH=$(uname -m); case "$ARCH" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo "Unsupported architecture: $ARCH" >&2;exit 1;; esac
if [ -z "$VERSION" ]; then
  if command -v curl >/dev/null 2>&1; then DATA=$(curl -fsSL --connect-timeout 8 "https://api.github.com/repos/$REPO/releases/latest")
  elif command -v wget >/dev/null 2>&1; then DATA=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest")
  else echo "curl or wget is required" >&2; exit 1; fi
  VERSION=$(printf '%s' "$DATA" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
fi
VERSION="v${VERSION#v}"
printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "Invalid release version: $VERSION" >&2; exit 1; }
if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL with Ed25519 support is required for secure first installation." >&2
  echo "NodeLume refuses to install an unverified binary." >&2
  exit 1
fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fetch(){ n="$1"; o="$2"; if [ -n "$LOCAL_DIR" ]; then cp "$LOCAL_DIR/$n" "$o"; elif command -v curl >/dev/null 2>&1; then curl -fL --retry 2 --connect-timeout 10 -o "$o" "https://github.com/$REPO/releases/download/$VERSION/$n"; elif command -v wget >/dev/null 2>&1; then wget -qO "$o" "https://github.com/$REPO/releases/download/$VERSION/$n"; else echo "curl or wget is required" >&2;exit 1;fi; }
BIN="nodelume-server-linux-$ARCH"
for f in "$BIN" checksums.txt checksums.sig release.pub update-server.sh; do fetch "$f" "$TMP/$f"; done
if [ "$(tr -d '\r\n' < "$TMP/release.pub")" != "$RELEASE_PUB" ]; then echo "Release public key mismatch" >&2; exit 1; fi
# Bootstrap trust without executing the downloaded NodeLume binary.
# Ed25519 SubjectPublicKeyInfo DER prefix: 302a300506032b6570032100.
printf '\060\052\060\005\006\003\053\145\160\003\041\000' > "$TMP/release-pub.der"
printf '%s' "$RELEASE_PUB" | openssl base64 -d -A >> "$TMP/release-pub.der" 2>/dev/null || { echo "Public key decode failed" >&2; exit 1; }
openssl base64 -d -A -in "$TMP/checksums.sig" -out "$TMP/checksums.sig.bin" 2>/dev/null || { echo "Signature decode failed" >&2; exit 1; }
if ! openssl pkeyutl -verify -pubin -inkey "$TMP/release-pub.der" -keyform DER -rawin -in "$TMP/checksums.txt" -sigfile "$TMP/checksums.sig.bin" >/dev/null 2>&1; then
  echo "Ed25519 release signature verification failed" >&2
  exit 1
fi
verify_sha256() {
  n="$1"
  WANT=$(awk -v f="$n" '$2==f||$2=="*"f{print $1;exit}' "$TMP/checksums.txt")
  [ -n "$WANT" ] || { echo "Checksum missing for $n" >&2; exit 1; }
  GOT=$(sha256sum "$TMP/$n" | awk '{print $1}')
  [ "$WANT" = "$GOT" ] || { echo "SHA256 verification failed for $n" >&2; exit 1; }
}
verify_sha256 "$BIN"
verify_sha256 update-server.sh
chmod 0755 "$TMP/$BIN"
"$TMP/$BIN" --self-check >/dev/null
"$TMP/$BIN" --version | grep -F "NodeLume Server v${VERSION#v} " >/dev/null || { echo "Downloaded binary version does not match $VERSION" >&2; exit 1; }
"$TMP/$BIN" --verify-file "$TMP/$BIN" --checksums "$TMP/checksums.txt" --signature "$TMP/checksums.sig" --public-key "$TMP/release.pub" >/dev/null
id nodelume >/dev/null 2>&1 || useradd --system --home-dir /var/lib/nodelume --shell /usr/sbin/nologin nodelume
install -d -m 0750 -o nodelume -g nodelume /var/lib/nodelume /var/lib/nodelume/acme
install -d -m 0770 -o root -g nodelume /var/lib/nodelume/update
install -d -m 0755 -o root -g root /etc/nodelume /usr/local/lib/nodelume
install -m 0755 "$TMP/$BIN" /usr/local/bin/nodelume-server
install -m 0644 "$TMP/release.pub" /etc/nodelume/release.pub
install -m 0755 "$TMP/update-server.sh" /usr/local/lib/nodelume/update-server.sh
cat > /etc/nodelume/server.env <<ENV
NODELUME_LISTEN=$LISTEN
NODELUME_PUBLIC_URL=$PUBLIC_URL
NODELUME_RELEASE_REPO=$REPO
ENV
chmod 0640 /etc/nodelume/server.env; chown root:nodelume /etc/nodelume/server.env
cat > /etc/systemd/system/nodelume-server.service <<'UNIT'
[Unit]
Description=NodeLume Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nodelume
Group=nodelume
EnvironmentFile=-/etc/nodelume/server.env
ExecStart=/usr/local/bin/nodelume-server --listen=${NODELUME_LISTEN} --public-url=${NODELUME_PUBLIC_URL} --repo=${NODELUME_RELEASE_REPO}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/nodelume
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/nodelume-server-update.path <<'UNIT'
[Unit]
Description=Watch NodeLume Server signed update request

[Path]
PathExists=/var/lib/nodelume/update/request.json
Unit=nodelume-server-update.service

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/nodelume-server-update.service <<'UNIT'
[Unit]
Description=NodeLume Server transactional updater
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/lib/nodelume/update-server.sh --request-file /var/lib/nodelume/update/request.json --status-file /var/lib/nodelume/update/status.json
PrivateTmp=true
ProtectHome=true
UNIT
systemctl daemon-reload
systemctl enable --now nodelume-server.service nodelume-server-update.path
printf '\nNodeLume Server %s installed.\nOpen http://%s (or your HTTPS reverse proxy) and create the administrator password on first visit.\n' "$VERSION" "$LISTEN"
