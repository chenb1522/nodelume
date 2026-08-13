#!/bin/sh
set -eu
REPO="chenb1522/nodelume"; VERSION=""; REQUEST=""; STATUS="/var/lib/nodelume/update/status.json"; LOCAL_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;; --version) VERSION="$2"; shift 2 ;; --request-file) REQUEST="$2"; shift 2 ;; --status-file) STATUS="$2"; shift 2 ;; --local-dir) LOCAL_DIR="$2"; shift 2 ;; *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "Run as root." >&2; exit 1; fi
BIN_PATH=${NODELUME_BIN_PATH:-/usr/local/bin/nodelume-server}; SYSTEMCTL=${NODELUME_SYSTEMCTL:-systemctl}; SERVICE=${NODELUME_SERVICE:-nodelume-server.service}; PUB=${NODELUME_PUBLIC_KEY:-/etc/nodelume/release.pub}
write_status() { mkdir -p "$(dirname "$STATUS")"; msg=$(printf '%s' "$2" | tr '"\\' '  '); printf '{"state":"%s","message":"%s","time":%s}\n' "$1" "$msg" "$(date +%s)" > "$STATUS.tmp"; mv "$STATUS.tmp" "$STATUS"; }
if [ -n "$REQUEST" ] && [ -f "$REQUEST" ]; then VERSION=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REQUEST" | head -1); rm -f "$REQUEST"; fi
if [ -z "$VERSION" ]; then
  if command -v curl >/dev/null 2>&1; then DATA=$(curl -fsSL --connect-timeout 8 "https://api.github.com/repos/$REPO/releases/latest")
  else DATA=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest"); fi
  VERSION=$(printf '%s' "$DATA" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
fi
VERSION="v${VERSION#v}"
if ! printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then write_status failed "invalid target version"; exit 1; fi
ARCH=$(uname -m); case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) write_status failed "unsupported architecture"; exit 1 ;; esac
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fetch() { n="$1"; o="$2"; if [ -n "$LOCAL_DIR" ]; then cp "$LOCAL_DIR/$n" "$o"; elif command -v curl >/dev/null 2>&1; then curl -fL --retry 2 --connect-timeout 10 -o "$o" "https://github.com/$REPO/releases/download/$VERSION/$n"; else wget -qO "$o" "https://github.com/$REPO/releases/download/$VERSION/$n"; fi; }
BIN="nodelume-server-linux-$ARCH"; write_status downloading "downloading $VERSION"
for f in "$BIN" checksums.txt checksums.sig; do fetch "$f" "$TMP/$f" || { write_status failed "download failed"; exit 1; }; done
if ! "$BIN_PATH" --verify-file "$TMP/$BIN" --checksums "$TMP/checksums.txt" --signature "$TMP/checksums.sig" --public-key "$PUB" >/dev/null; then write_status failed "signature or checksum verification failed"; exit 1; fi
chmod 0755 "$TMP/$BIN"
if ! "$TMP/$BIN" --self-check >/dev/null; then write_status failed "new binary self-check failed"; exit 1; fi
NEW_INFO=$("$TMP/$BIN" --version 2>/dev/null || true)
printf '%s' "$NEW_INFO" | grep -F "NodeLume Server ${VERSION} " >/dev/null || { write_status failed "downloaded binary version does not match target"; exit 1; }
CUR_INFO=$("$BIN_PATH" --version 2>/dev/null || true)
CUR_PROTO=$(printf '%s' "$CUR_INFO" | sed -n 's/.*protocol \([0-9][0-9]*\).*/\1/p')
NEW_PROTO=$(printf '%s' "$NEW_INFO" | sed -n 's/.*protocol \([0-9][0-9]*\).*/\1/p')
if [ -z "$CUR_PROTO" ] || [ -z "$NEW_PROTO" ] || [ "$CUR_PROTO" != "$NEW_PROTO" ]; then
  write_status failed "protocol compatibility check failed; update through a migration-capable release first"
  exit 1
fi
PREV="$BIN_PATH.previous"; rm -f "$PREV"; cp -p "$BIN_PATH" "$PREV"; write_status installing "backup created; installing $VERSION"; install -m 0755 "$TMP/$BIN" "$BIN_PATH"
if ! "$SYSTEMCTL" restart "$SERVICE"; then cp -p "$PREV" "$BIN_PATH"; "$SYSTEMCTL" restart "$SERVICE" || true; write_status rolled_back "new version failed to start; previous version restored"; exit 1; fi
health_url=${NODELUME_HEALTH_URL:-}
if [ -z "$health_url" ] && [ -r /etc/nodelume/server.env ]; then
  listen=$(sed -n 's/^NODELUME_LISTEN=//p' /etc/nodelume/server.env | head -1); host=${listen%:*}; port=${listen##*:}; [ "$host" = "0.0.0.0" ] && host=127.0.0.1; [ "$host" = "::" ] && host=127.0.0.1; health_url="http://$host:$port/healthz"
fi
[ -n "$health_url" ] || health_url="http://127.0.0.1:8080/healthz"
http_health() { if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$health_url" >/dev/null 2>&1; else wget -q -T 2 -O /dev/null "$health_url" >/dev/null 2>&1; fi; }
ok=0; i=0
while [ $i -lt 25 ]; do if "$SYSTEMCTL" is-active --quiet "$SERVICE" && http_health; then ok=1; break; fi; i=$((i+1)); sleep 1; done
if [ $ok -ne 1 ]; then cp -p "$PREV" "$BIN_PATH"; "$SYSTEMCTL" restart "$SERVICE" || true; write_status rolled_back "HTTP health check failed; previous version restored"; exit 1; fi
write_status success "updated to $VERSION"; echo "NodeLume Server updated to $VERSION"
