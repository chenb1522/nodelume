#!/bin/sh
set -eu
REPO="chenb1522/nodelume"
VERSION=""
SERVER=""
TOKEN=""
LOCAL_DIR=""
ALLOW_INSECURE_HTTP=0
RELEASE_PUB="HuKgHCbJ3RDisYmD0u0sI0Jj86cQJJa7KVzDKvNAK4U="
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --local-dir) LOCAL_DIR="$2"; shift 2 ;;
    --allow-insecure-http) ALLOW_INSECURE_HTTP=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "Run as root." >&2; exit 1; fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then echo "--server and --token are required" >&2; exit 2; fi
case "$SERVER" in
  https://*) ;;
  http://127.0.0.1*|http://localhost*) ;;
  http://*)
    if [ "$ALLOW_INSECURE_HTTP" -ne 1 ]; then
      echo "Refusing plain HTTP to a remote NodeLume Server. Configure HTTPS first." >&2
      echo "For isolated testing only, pass --allow-insecure-http explicitly." >&2
      exit 1
    fi
    ;;
  *) echo "Server URL must start with https:// (or http:// for explicit testing)." >&2; exit 1 ;;
esac
if ! command -v systemctl >/dev/null 2>&1; then echo "NodeLume Agent requires systemd." >&2; exit 1; fi
ARCH=$(uname -m)
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; esac
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
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fetch() {
  n="$1"; o="$2"
  if [ -n "$LOCAL_DIR" ]; then cp "$LOCAL_DIR/$n" "$o"
  elif command -v curl >/dev/null 2>&1; then curl -fL --retry 2 --connect-timeout 10 -o "$o" "https://github.com/$REPO/releases/download/$VERSION/$n"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$o" "https://github.com/$REPO/releases/download/$VERSION/$n"
  else echo "curl or wget is required" >&2; exit 1; fi
}
BIN="nodelume-agent-linux-$ARCH"
for f in "$BIN" checksums.txt checksums.sig release.pub; do fetch "$f" "$TMP/$f"; done
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
WANT=$(awk -v f="$BIN" '$2==f||$2=="*"f{print $1;exit}' "$TMP/checksums.txt")
GOT=$(sha256sum "$TMP/$BIN" | awk '{print $1}')
if [ -z "$WANT" ] || [ "$WANT" != "$GOT" ]; then echo "SHA256 verification failed" >&2; exit 1; fi
chmod 0755 "$TMP/$BIN"
"$TMP/$BIN" --self-check >/dev/null
"$TMP/$BIN" --version | grep -F "NodeLume Agent v${VERSION#v} " >/dev/null || { echo "Downloaded binary version does not match $VERSION" >&2; exit 1; }
"$TMP/$BIN" --verify-file "$TMP/$BIN" --checksums "$TMP/checksums.txt" --signature "$TMP/checksums.sig" --public-key "$TMP/release.pub" >/dev/null
if ! id nodelume-agent >/dev/null 2>&1; then useradd --system --home-dir /var/lib/nodelume-agent --shell /usr/sbin/nologin nodelume-agent; fi
install -d -m 0750 -o nodelume-agent -g nodelume-agent /var/lib/nodelume-agent
install -d -m 0700 -o root -g root /var/lib/nodelume-agent-helper /var/lib/nodelume-agent-helper/update
install -d -m 0755 -o root -g root /etc/nodelume
install -m 0755 "$TMP/$BIN" /usr/local/bin/nodelume-agent
install -m 0644 "$TMP/release.pub" /etc/nodelume/release.pub
cat > /var/lib/nodelume-agent/agent.json <<JSON
{"server":"$SERVER","enrollment_token":"$TOKEN","release_repo":"$REPO","allow_insecure_http":$([ "$ALLOW_INSECURE_HTTP" -eq 1 ] && echo true || echo false)}
JSON
chown nodelume-agent:nodelume-agent /var/lib/nodelume-agent/agent.json
chmod 0600 /var/lib/nodelume-agent/agent.json
cat > /etc/systemd/system/nodelume-agent.socket <<'UNIT'
[Unit]
Description=NodeLume privileged helper socket
[Socket]
ListenStream=/run/nodelume-agent/helper.sock
SocketMode=0660
SocketUser=root
SocketGroup=nodelume-agent
DirectoryMode=0755
Service=nodelume-agent-helper.service
RemoveOnStop=true
[Install]
WantedBy=sockets.target
UNIT
cat > /etc/systemd/system/nodelume-agent-helper.service <<'UNIT'
[Unit]
Description=NodeLume privileged on-demand helper
Requires=nodelume-agent.socket
After=nodelume-agent.socket
[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/nodelume-agent --helper
PrivateTmp=true
ProtectHome=true
UMask=0077
UNIT
cat > /etc/systemd/system/nodelume-agent.service <<'UNIT'
[Unit]
Description=NodeLume Agent
After=network-online.target nodelume-agent.socket
Wants=network-online.target
Requires=nodelume-agent.socket
[Service]
Type=simple
User=nodelume-agent
Group=nodelume-agent
ExecStart=/usr/local/bin/nodelume-agent --config /var/lib/nodelume-agent/agent.json
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/nodelume-agent
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now nodelume-agent.socket nodelume-agent.service
echo "NodeLume Agent $VERSION installed and enrollment started."
