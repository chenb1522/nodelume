#!/bin/sh
set -eu
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
systemctl disable --now nodelume-agent.service nodelume-agent.socket 2>/dev/null || true
rm -f /etc/systemd/system/nodelume-agent.service /etc/systemd/system/nodelume-agent.socket /etc/systemd/system/nodelume-agent-helper.service
systemctl daemon-reload || true
rm -f /usr/local/bin/nodelume-agent /usr/local/bin/nodelume-agent.previous
if [ "$PURGE" -eq 1 ]; then
  rm -rf /var/lib/nodelume-agent /var/lib/nodelume-agent-helper
  userdel nodelume-agent 2>/dev/null || true
  # Keep the shared release trust anchor if the Server is installed here too.
  if [ ! -x /usr/local/bin/nodelume-server ] && [ ! -f /etc/systemd/system/nodelume-server.service ]; then
    rm -f /etc/nodelume/release.pub
    rmdir /etc/nodelume 2>/dev/null || true
  fi
  echo "NodeLume Agent fully removed. Shared Server trust data was preserved if a Server is installed."
else
  echo "NodeLume Agent removed; enrollment config was kept. Use --purge to delete Agent data."
fi
