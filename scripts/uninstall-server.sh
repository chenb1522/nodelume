#!/bin/sh
set -eu
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
systemctl disable --now nodelume-server-update.path nodelume-server.service 2>/dev/null || true
rm -f /etc/systemd/system/nodelume-server.service /etc/systemd/system/nodelume-server-update.path /etc/systemd/system/nodelume-server-update.service
systemctl daemon-reload || true
rm -f /usr/local/bin/nodelume-server /usr/local/bin/nodelume-server.previous
rm -rf /usr/local/lib/nodelume
if [ "$PURGE" -eq 1 ]; then
  rm -f /etc/nodelume/server.env
  rm -rf /var/lib/nodelume
  userdel nodelume 2>/dev/null || true
  # release.pub is shared when Server and Agent are intentionally co-installed.
  if [ ! -x /usr/local/bin/nodelume-agent ] && [ ! -f /etc/systemd/system/nodelume-agent.service ]; then
    rm -f /etc/nodelume/release.pub
  fi
  rmdir /etc/nodelume 2>/dev/null || true
  echo "NodeLume Server fully removed. Shared Agent trust data was preserved if an Agent is installed."
else
  echo "NodeLume Server removed; /etc/nodelume/server.env and /var/lib/nodelume were kept. Use --purge to delete Server data."
fi
