#!/bin/sh
set -eu
REPO="chenb1522/nodelume"
VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "Run as root." >&2; exit 1; fi
if [ -z "$VERSION" ]; then
  if command -v curl >/dev/null 2>&1; then DATA=$(curl -fsSL --connect-timeout 8 "https://api.github.com/repos/$REPO/releases/latest")
  else DATA=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest"); fi
  VERSION=$(printf '%s' "$DATA" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
fi
VERSION="v${VERSION#v}"
echo "Updating NodeLume Agent to $VERSION..."
/usr/local/bin/nodelume-agent --upgrade-self "$VERSION" --repo "$REPO" --public-key /etc/nodelume/release.pub
systemctl restart nodelume-agent.service
i=0
while [ $i -lt 35 ]; do
  if [ ! -f /var/lib/nodelume-agent-helper/update/pending.json ] && systemctl is-active --quiet nodelume-agent.service; then
    echo "NodeLume Agent update succeeded: $VERSION"
    exit 0
  fi
  i=$((i+1)); sleep 1
done
echo "Agent failed health check; rolling back..." >&2
if ! /usr/local/bin/nodelume-agent --rollback; then
  if [ -x /usr/local/bin/nodelume-agent.previous ]; then mv -f /usr/local/bin/nodelume-agent.previous /usr/local/bin/nodelume-agent; fi
fi
systemctl restart nodelume-agent.service || true
echo "Update failed; previous Agent restored." >&2
exit 1
