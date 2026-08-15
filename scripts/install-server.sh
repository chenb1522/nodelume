#!/bin/sh
set -eu
VERSION=latest
LISTEN=""
LOCAL_DIR=""
REPO=${NODELUME_RELEASE_REPO:-chenb1522/nodelume}
PUB='HuKgHCbJ3RDisYmD0u0sI0Jj86cQJJa7KVzDKvNAK4U='
VERIFIER_SHA_AMD64='b408dff9c54e194c9a437388beebe1bc010abf969499caba629f026d8dde3a27'
VERIFIER_SHA_ARM64='9fd8c596ea5f6a86b8f8a137786b641815e7159191364af9f685f6f3b914649e'

info(){ printf '\033[34m[INFO]\033[0m %s\n' "$*"; }
ok(){ printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
fail(){ printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2; }
if [ ! -t 1 ]; then info(){ printf '[INFO] %s\n' "$*"; }; ok(){ printf '[ OK ] %s\n' "$*"; }; fail(){ printf '[FAIL] %s\n' "$*" >&2; }; fi
usage(){ cat <<'EOF'
NodeLume Server Installer
  -l, --listen ADDRESS:PORT   首次安装监听地址（默认 0.0.0.0:随机空闲端口）
  -v, --version VERSION      版本，默认 latest
  -r, --repo OWNER/REPO      Release 仓库
  -L DIR                     本地 Release 目录（测试/离线安装）
EOF
}
while [ $# -gt 0 ]; do
  case "$1" in
    -l|--listen) [ $# -ge 2 ] || exit 2; LISTEN=$2; shift 2;;
    -v|--version) [ $# -ge 2 ] || exit 2; VERSION=$2; shift 2;;
    -r|--repo) [ $# -ge 2 ] || exit 2; REPO=$2; shift 2;;
    -L) [ $# -ge 2 ] || exit 2; LOCAL_DIR=$2; shift 2;;
    -h|--help) usage; exit 0;;
    *) fail "未知参数: $1"; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { fail '需要 root 权限'; exit 5; }
command -v systemctl >/dev/null 2>&1 || { fail '当前系统没有 systemd'; exit 1; }
case $(uname -m) in x86_64|amd64) ARCH=amd64; PIN=$VERIFIER_SHA_AMD64;; aarch64|arm64) ARCH=arm64; PIN=$VERIFIER_SHA_ARM64;; *) fail '不支持当前 CPU 架构'; exit 1;; esac
case "$REPO" in */*) ;; *) fail '仓库格式无效'; exit 2;; esac
LOCK=/run/lock/nodelume-server-install.lock
mkdir -p /run/lock 2>/dev/null || LOCK=/tmp/nodelume-server-install.lock
if ! mkdir "$LOCK" 2>/dev/null; then fail 'NodeLume Server 安装/更新正在进行'; exit 1; fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"; rmdir "$LOCK" 2>/dev/null || true' EXIT INT TERM
fetch_url(){ u=$1; o=$2; if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 2 --connect-timeout 10 -o "$o" "$u"; elif command -v wget >/dev/null 2>&1; then wget -qO "$o" "$u"; else return 127; fi; }
latest_tag(){ if [ -n "$LOCAL_DIR" ]; then printf 'v1.0.2'; return; fi; f="$TMP/latest.json"; fetch_url "https://api.github.com/repos/$REPO/releases/latest" "$f" || return 1; sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1; }
if [ "$VERSION" = latest ]; then VERSION=$(latest_tag) || { fail '无法查询最新 Release'; exit 3; }; fi
VERSION="v${VERSION#v}"
printf %s "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { fail 'VERSION_NOT_FOUND'; exit 4; }
vercmp(){ awk -v a="${1#v}" -v b="${2#v}" 'BEGIN{split(a,A,".");split(b,B,".");for(i=1;i<=3;i++){if((A[i]+0)>(B[i]+0)){print 1;exit}if((A[i]+0)<(B[i]+0)){print -1;exit}}print 0}'; }
CURRENT=""
if [ -x /usr/local/bin/nodelume-server ]; then CURRENT=$(/usr/local/bin/nodelume-server --version 2>/dev/null | sed -n 's/.* v\([0-9][^ ]*\).*/v\1/p' | head -1); fi
if [ -n "$CURRENT" ]; then
  cmp=$(vercmp "$CURRENT" "$VERSION")
  if [ "$cmp" -eq 0 ]; then
    state=$(systemctl is-active nodelume-server 2>/dev/null || true)
    listen=$(sed -n 's/^NODELUME_LISTEN=//p' /etc/nodelume/server.env 2>/dev/null | head -1)
    printf '\n✅ NodeLume Server %s 已安装\n\n状态      %s\n监听      %s\n' "$CURRENT" "${state:-未知}" "${listen:-由配置文件管理}"
    exit 0
  fi
  if [ "$cmp" -gt 0 ]; then fail "拒绝降级：当前 $CURRENT，请求 $VERSION"; exit 4; fi
fi
BASE="https://github.com/$REPO/releases/download/$VERSION"
fetch(){ n=$1; o=$2; if [ -n "$LOCAL_DIR" ]; then cp "$LOCAL_DIR/$n" "$o"; else fetch_url "$BASE/$n" "$o"; fi; }
BIN=nodelume-server-linux-$ARCH; VER=nodelume-verify-linux-$ARCH
for f in "$BIN" "$VER" nlm install-server.sh checksums.txt checksums.sig release.pub; do fetch "$f" "$TMP/$f" || { fail "VERSION_NOT_FOUND: $VERSION ($f)"; exit 4; }; done
[ "$(tr -d '\r\n' < "$TMP/release.pub")" = "$PUB" ] || { fail 'Release 公钥不匹配'; exit 1; }
if [ "$PIN" = '__VERIFIER_SHA_AMD64__' ] || [ "$PIN" = '__VERIFIER_SHA_ARM64__' ]; then fail '安装器缺少 verifier 固定校验值'; exit 1; fi
got_ver=$(sha256sum "$TMP/$VER" | awk '{print $1}'); [ "$got_ver" = "$PIN" ] || { fail 'Release verifier SHA256 不匹配'; exit 1; }
chmod 0755 "$TMP/$VER"
"$TMP/$VER" "$TMP/release.pub" "$TMP/checksums.txt" "$TMP/checksums.sig" >/dev/null || { fail 'Ed25519 Release 签名验证失败'; exit 1; }
verify_sha(){ n=$1; want=$(awk -v f="$n" '$2==f||$2=="*"f{print $1;exit}' "$TMP/checksums.txt"); [ -n "$want" ] || return 1; got=$(sha256sum "$TMP/$n"|awk '{print $1}'); [ "$want" = "$got" ]; }
for f in "$BIN" "$VER" nlm install-server.sh; do verify_sha "$f" || { fail "SHA256 校验失败: $f"; exit 1; }; done
chmod 0755 "$TMP/$BIN"; "$TMP/$BIN" --self-check >/dev/null || { fail '新 Server 二进制自检失败'; exit 1; }
if [ -z "$LISTEN" ] && [ -f /etc/nodelume/server.env ]; then LISTEN=$(sed -n 's/^NODELUME_LISTEN=//p' /etc/nodelume/server.env | head -1); fi
if [ -z "$LISTEN" ] && [ -z "$CURRENT" ]; then PORT=$($TMP/$BIN --pick-port); LISTEN="0.0.0.0:$PORT"; fi
[ -n "$LISTEN" ] || LISTEN="0.0.0.0:19770"
printf %s "$LISTEN" | grep -Eq '^([^:]+|\[[^]]+\]):[0-9]+$' || { fail '监听地址格式无效'; exit 2; }
BACK="$TMP/backup"; mkdir -p "$BACK"
for f in /usr/local/bin/nodelume-server /usr/local/bin/nlm /usr/local/lib/nodelume/install-server.sh /etc/nodelume/server.env /etc/nodelume/release.pub /etc/systemd/system/nodelume-server.service /etc/systemd/system/nodelume-server-update.path /etc/systemd/system/nodelume-server-update.service /var/lib/nodelume/state.json; do [ -e "$f" ] && cp -a "$f" "$BACK/$(printf %s "$f" | tr / _)"; done
restore_or_remove(){ src=$1; dst=$2; if [ -f "$BACK/$src" ]; then cp -a "$BACK/$src" "$dst"; else rm -f "$dst"; fi; }
rollback(){
  fail '新版本启动/健康检查失败，正在回滚'
  restore_or_remove _usr_local_bin_nodelume-server /usr/local/bin/nodelume-server
  restore_or_remove _usr_local_bin_nlm /usr/local/bin/nlm
  restore_or_remove _usr_local_lib_nodelume_install-server.sh /usr/local/lib/nodelume/install-server.sh
  restore_or_remove _etc_nodelume_server.env /etc/nodelume/server.env
  restore_or_remove _etc_nodelume_release.pub /etc/nodelume/release.pub
  restore_or_remove _etc_systemd_system_nodelume-server.service /etc/systemd/system/nodelume-server.service
  restore_or_remove _etc_systemd_system_nodelume-server-update.path /etc/systemd/system/nodelume-server-update.path
  restore_or_remove _etc_systemd_system_nodelume-server-update.service /etc/systemd/system/nodelume-server-update.service
  [ -f "$BACK/_var_lib_nodelume_state.json" ] && cp -a "$BACK/_var_lib_nodelume_state.json" /var/lib/nodelume/state.json
  systemctl daemon-reload >/dev/null 2>&1 || true; systemctl restart nodelume-server >/dev/null 2>&1 || true
}
id nodelume >/dev/null 2>&1 || useradd --system --home-dir /var/lib/nodelume --shell /usr/sbin/nologin nodelume
install -d -m0750 -o nodelume -g nodelume /var/lib/nodelume /var/lib/nodelume/acme /var/lib/nodelume/logs /var/lib/nodelume/update
install -d -m0755 /etc/nodelume /usr/local/lib/nodelume
install -m0755 "$TMP/$BIN" /usr/local/bin/nodelume-server
install -m0755 "$TMP/nlm" /usr/local/bin/nlm
install -m0755 "$TMP/install-server.sh" /usr/local/lib/nodelume/install-server.sh
install -m0644 "$TMP/release.pub" /etc/nodelume/release.pub
if [ ! -f /etc/nodelume/server.env ] || [ -n "${LISTEN:-}" ]; then
  { printf 'NODELUME_LISTEN=%s\n' "$LISTEN"; printf 'NODELUME_RELEASE_REPO=%s\n' "$REPO"; } > /etc/nodelume/server.env
  chown root:nodelume /etc/nodelume/server.env; chmod 0640 /etc/nodelume/server.env
fi
cat >/etc/systemd/system/nodelume-server.service <<'UNIT'
[Unit]
Description=NodeLume Server
After=network-online.target
Wants=network-online.target
[Service]
User=nodelume
Group=nodelume
EnvironmentFile=/etc/nodelume/server.env
ExecStart=/usr/local/bin/nodelume-server --listen=${NODELUME_LISTEN}
Restart=always
RestartSec=2
RuntimeDirectory=nodelume-server
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWriteDirectories=/var/lib/nodelume /run/nodelume-server
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/nodelume-server-update.path <<'UNIT'
[Unit]
Description=NodeLume Server safe update request watcher
[Path]
PathExists=/var/lib/nodelume/update/request.json
Unit=nodelume-server-update.service
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/nodelume-server-update.service <<'UNIT'
[Unit]
Description=NodeLume Server safe updater
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/nlm server apply-update-request
UNIT
systemctl daemon-reload >/dev/null
systemctl enable nodelume-server.service nodelume-server-update.path >/dev/null 2>&1 || true
systemctl restart nodelume-server.service >/dev/null 2>&1 || { rollback; exit 1; }
systemctl start nodelume-server-update.path >/dev/null 2>&1 || true
health=0
port=${LISTEN##*:}; port=${port#]};
probe_health(){
  for scheme in http https; do
    if command -v curl >/dev/null 2>&1; then
      curl -kfsS --max-time 2 "$scheme://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return 0
      curl -gkfsS --max-time 2 "$scheme://[::1]:$port/healthz" >/dev/null 2>&1 && return 0
    elif command -v wget >/dev/null 2>&1; then
      wget -q --timeout=2 --no-check-certificate -O /dev/null "$scheme://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return 0
    fi
  done
  return 1
}
for i in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet nodelume-server.service && probe_health; then health=1; break; fi
  sleep 1
done
[ "$health" -eq 1 ] || { rollback; exit 1; }
ok 'Release 验证通过'; ok 'Server 服务已启动'
ip=$(hostname -I 2>/dev/null | awk '{print $1}'); [ -n "$ip" ] || ip='<SERVER_IP>'
printf '\n✅ NodeLume Server 安装/升级成功\n\n版本      %s\n状态      运行中\n监听      %s\n访问      http://%s:%s\n\n常用命令\n  nlm server s        查看运行状态\n  nlm server s -d     查看详细资源占用\n  nlm server u        更新到最新版本\n  nlm server r        重启 Server\n  nlm server rm       卸载 Server\n  nlm help            查看全部命令\n' "$VERSION" "$LISTEN" "$ip" "$port"
