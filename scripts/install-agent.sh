#!/bin/sh
set -eu
VERSION=latest; SERVER=""; TOKEN=""; NAME=""; LOCAL_DIR=""; REPO=${NODELUME_RELEASE_REPO:-chenb1522/nodelume}
PUB='HuKgHCbJ3RDisYmD0u0sI0Jj86cQJJa7KVzDKvNAK4U='
VERIFIER_SHA_AMD64='70a31e6f2d2232be9ccbaf2b5c40c745547fb6656a68f558ea981743434679cf'; VERIFIER_SHA_ARM64='6cd3ec1ff2e3577de935af02ed43f86062382295087f9ed3ff22e9d12f77d728'
info(){ printf '\033[34m[INFO]\033[0m %s\n' "$*"; }; ok(){ printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }; fail(){ printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2; }; if [ ! -t 1 ]; then info(){ printf '[INFO] %s\n' "$*"; }; ok(){ printf '[ OK ] %s\n' "$*"; }; fail(){ printf '[FAIL] %s\n' "$*" >&2; }; fi
usage(){ cat <<'EOF'
NodeLume Agent Installer
  -s, --server URL
  -t, --token TOKEN
  -n, --name NAME
  -v, --version VERSION
  -r, --repo OWNER/REPO
  -L DIR
EOF
}
while [ $# -gt 0 ]; do case "$1" in -s|--server) SERVER=$2;shift 2;;-t|--token)TOKEN=$2;shift 2;;-n|--name)NAME=$2;shift 2;;-v|--version)VERSION=$2;shift 2;;-r|--repo)REPO=$2;shift 2;;-L)LOCAL_DIR=$2;shift 2;;-h|--help)usage;exit 0;;*)fail "未知参数: $1";exit 2;;esac;done
[ "$(id -u)" -eq 0 ] || { fail '需要 root 权限'; exit 5; }; command -v systemctl >/dev/null 2>&1 || { fail '当前系统没有 systemd'; exit 1; }
case $(uname -m) in x86_64|amd64)ARCH=amd64;PIN=$VERIFIER_SHA_AMD64;;aarch64|arm64)ARCH=arm64;PIN=$VERIFIER_SHA_ARM64;;*)fail '不支持当前 CPU 架构';exit 1;;esac
LOCK=/run/lock/nodelume-agent-install.lock; mkdir -p /run/lock 2>/dev/null || LOCK=/tmp/nodelume-agent-install.lock; mkdir "$LOCK" 2>/dev/null || { fail 'Agent 安装/更新正在进行';exit 1; }
TMP=$(mktemp -d);trap 'rm -rf "$TMP";rmdir "$LOCK" 2>/dev/null||true' EXIT INT TERM
fetch_url(){ u=$1;o=$2;if command -v curl >/dev/null 2>&1;then curl -fsSL --retry 2 --connect-timeout 10 -o "$o" "$u";elif command -v wget >/dev/null 2>&1;then wget -qO "$o" "$u";else return 127;fi; }
if [ "$VERSION" = latest ]; then if [ -n "$LOCAL_DIR" ];then VERSION=v1.0.1;else fetch_url "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"||{ fail '无法查询最新 Release';exit 3;};VERSION=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/latest.json"|head -1);fi;fi
VERSION="v${VERSION#v}";printf %s "$VERSION"|grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'||{ fail 'VERSION_NOT_FOUND';exit 4; }
vercmp(){ awk -v a="${1#v}" -v b="${2#v}" 'BEGIN{split(a,A,".");split(b,B,".");for(i=1;i<=3;i++){if((A[i]+0)>(B[i]+0)){print 1;exit}if((A[i]+0)<(B[i]+0)){print -1;exit}}print 0}'; }
CURRENT="";[ -x /usr/local/bin/nodelume-agent ]&&CURRENT=$(/usr/local/bin/nodelume-agent --version 2>/dev/null|sed -n 's/.* v\([0-9][^ ]*\).*/v\1/p'|head -1)
if [ -n "$CURRENT" ];then
  cmp=$(vercmp "$CURRENT" "$VERSION")
  if [ "$cmp" -eq 0 ];then
    if [ -n "$SERVER" ] || [ -n "$TOKEN" ];then
      [ -n "$SERVER" ]&&[ -n "$TOKEN" ]||{ fail '绑定需要同时提供 -s Server 与 -t Token';exit 2;}
      if [ -n "$NAME" ];then /usr/local/bin/nodelume-agent bind --config /var/lib/nodelume-agent/agent.json -s "$SERVER" -t "$TOKEN" -n "$NAME";else /usr/local/bin/nodelume-agent bind --config /var/lib/nodelume-agent/agent.json -s "$SERVER" -t "$TOKEN";fi
      chown nodelume-agent:nodelume-agent /var/lib/nodelume-agent/agent.json 2>/dev/null||true
      systemctl restart nodelume-agent.service >/dev/null 2>&1||true
      printf '\n✅ NodeLume Agent %s 已安装并完成绑定\n' "$CURRENT"
    else
      printf '\n✅ NodeLume Agent %s 已安装\n' "$CURRENT"
      /usr/local/bin/nlm agent s 2>/dev/null||true
    fi
    exit 0
  fi
  if [ "$cmp" -gt 0 ];then fail "拒绝降级：当前 $CURRENT，请求 $VERSION";exit 4;fi
fi
BASE="https://github.com/$REPO/releases/download/$VERSION"; fetch(){ n=$1;o=$2;if [ -n "$LOCAL_DIR" ];then cp "$LOCAL_DIR/$n" "$o";else fetch_url "$BASE/$n" "$o";fi; }
BIN=nodelume-agent-linux-$ARCH;VER=nodelume-verify-linux-$ARCH
for f in "$BIN" "$VER" nlm install-agent.sh checksums.txt checksums.sig release.pub;do fetch "$f" "$TMP/$f"||{ fail "VERSION_NOT_FOUND: $VERSION ($f)";exit 4;};done
[ "$(tr -d '\r\n'<"$TMP/release.pub")" = "$PUB" ]||{ fail 'Release 公钥不匹配';exit 1;};[ "$PIN" != '__VERIFIER_SHA_AMD64__' ]&&[ "$PIN" != '__VERIFIER_SHA_ARM64__' ]||{ fail '安装器缺少 verifier 固定校验值';exit 1;};got=$(sha256sum "$TMP/$VER"|awk '{print $1}');[ "$got" = "$PIN" ]||{ fail 'Release verifier SHA256 不匹配';exit 1;};chmod 0755 "$TMP/$VER";"$TMP/$VER" "$TMP/release.pub" "$TMP/checksums.txt" "$TMP/checksums.sig" >/dev/null||{ fail 'Release 签名验证失败';exit 1;}
verify_sha(){ n=$1;want=$(awk -v f="$n" '$2==f||$2=="*"f{print $1;exit}' "$TMP/checksums.txt");got=$(sha256sum "$TMP/$n"|awk '{print $1}');[ -n "$want" ]&&[ "$want" = "$got" ];};for f in "$BIN" "$VER" nlm install-agent.sh;do verify_sha "$f"||{ fail "SHA256 校验失败: $f";exit 1;};done
chmod 0755 "$TMP/$BIN";"$TMP/$BIN" --self-check >/dev/null||{ fail '新 Agent 二进制自检失败';exit 1;}
BACK="$TMP/backup";mkdir -p "$BACK";for f in /usr/local/bin/nodelume-agent /usr/local/bin/nlm /usr/local/lib/nodelume/install-agent.sh /var/lib/nodelume-agent/agent.json /etc/nodelume/release.pub /etc/systemd/system/nodelume-agent.service /etc/systemd/system/nodelume-agent-helper.socket /etc/systemd/system/nodelume-agent-helper.service;do [ -e "$f" ]&&cp -a "$f" "$BACK/$(printf %s "$f"|tr / _)";done
restore_or_remove(){ src=$1;dst=$2;if [ -f "$BACK/$src" ];then cp -a "$BACK/$src" "$dst";else rm -f "$dst";fi;}
rollback(){ fail '新 Agent 启动/连接测试失败，正在回滚';restore_or_remove _usr_local_bin_nodelume-agent /usr/local/bin/nodelume-agent;restore_or_remove _usr_local_bin_nlm /usr/local/bin/nlm;restore_or_remove _usr_local_lib_nodelume_install-agent.sh /usr/local/lib/nodelume/install-agent.sh;restore_or_remove _var_lib_nodelume-agent_agent.json /var/lib/nodelume-agent/agent.json;restore_or_remove _etc_nodelume_release.pub /etc/nodelume/release.pub;restore_or_remove _etc_systemd_system_nodelume-agent.service /etc/systemd/system/nodelume-agent.service;restore_or_remove _etc_systemd_system_nodelume-agent-helper.socket /etc/systemd/system/nodelume-agent-helper.socket;restore_or_remove _etc_systemd_system_nodelume-agent-helper.service /etc/systemd/system/nodelume-agent-helper.service;systemctl daemon-reload >/dev/null 2>&1||true;systemctl restart nodelume-agent >/dev/null 2>&1||true; }
id nodelume-agent >/dev/null 2>&1||useradd --system --home-dir /var/lib/nodelume-agent --shell /usr/sbin/nologin nodelume-agent
install -d -m0750 -o nodelume-agent -g nodelume-agent /var/lib/nodelume-agent;install -d -m0755 /etc/nodelume /usr/local/lib/nodelume
install -m0755 "$TMP/$BIN" /usr/local/bin/nodelume-agent;install -m0755 "$TMP/nlm" /usr/local/bin/nlm;install -m0755 "$TMP/install-agent.sh" /usr/local/lib/nodelume/install-agent.sh;install -m0644 "$TMP/release.pub" /etc/nodelume/release.pub
[ -f /var/lib/nodelume-agent/agent.json ]||printf '{"config_version":2,"report_interval_sec":2}\n'>/var/lib/nodelume-agent/agent.json
chown nodelume-agent:nodelume-agent /var/lib/nodelume-agent/agent.json;chmod 0600 /var/lib/nodelume-agent/agent.json
cat >/etc/systemd/system/nodelume-agent-helper.socket <<'UNIT'
[Unit]
Description=NodeLume Agent privileged helper socket
[Socket]
ListenStream=/run/nodelume-agent/helper.sock
SocketUser=root
SocketGroup=nodelume-agent
SocketMode=0660
RemoveOnStop=true
[Install]
WantedBy=sockets.target
UNIT
cat >/etc/systemd/system/nodelume-agent-helper.service <<'UNIT'
[Unit]
Description=NodeLume Agent privileged helper
[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/nodelume-agent --helper
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/usr/local/bin /var/lib/nodelume-agent /run/nodelume-agent
UNIT
cat >/etc/systemd/system/nodelume-agent.service <<'UNIT'
[Unit]
Description=NodeLume Agent
After=network-online.target
Wants=network-online.target
[Service]
User=nodelume-agent
Group=nodelume-agent
ExecStart=/usr/local/bin/nodelume-agent --config /var/lib/nodelume-agent/agent.json
Restart=always
RestartSec=3
RuntimeDirectory=nodelume-agent
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/nodelume-agent /run/nodelume-agent
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload >/dev/null;systemctl enable --now nodelume-agent-helper.socket >/dev/null 2>&1||true
if [ -n "$SERVER" ] || [ -n "$TOKEN" ]; then
  [ -n "$SERVER" ] && [ -n "$TOKEN" ] || { fail '绑定需要同时提供 -s Server 与 -t Token'; rollback; exit 2; }
  if [ -n "$NAME" ]; then
    /usr/local/bin/nodelume-agent bind --config /var/lib/nodelume-agent/agent.json -s "$SERVER" -t "$TOKEN" -n "$NAME" || { rollback; exit 1; }
  else
    /usr/local/bin/nodelume-agent bind --config /var/lib/nodelume-agent/agent.json -s "$SERVER" -t "$TOKEN" || { rollback; exit 1; }
  fi
  chown nodelume-agent:nodelume-agent /var/lib/nodelume-agent/agent.json
fi
systemctl enable nodelume-agent.service >/dev/null 2>&1||true;systemctl restart nodelume-agent.service >/dev/null 2>&1||{ rollback;exit 1;};sleep 1;systemctl is-active --quiet nodelume-agent.service||{ rollback;exit 1;}
if grep -Eq '"node_id"[[:space:]]*:[[:space:]]*"[^"]+"' /var/lib/nodelume-agent/agent.json 2>/dev/null;then /usr/local/bin/nodelume-agent test --config /var/lib/nodelume-agent/agent.json >/dev/null 2>&1||{ rollback;exit 1;};fi
status=未绑定;grep -Eq '"node_id"[[:space:]]*:[[:space:]]*"[^"]+"' /var/lib/nodelume-agent/agent.json 2>/dev/null&&status=已绑定
ok 'Release 验证通过';printf '\n✅ NodeLume Agent 安装/升级成功\n\n版本      %s\n状态      %s\n' "$VERSION" "$status"
[ "$status" = 未绑定 ]&&printf '\n绑定 Server\n  nlm agent bind -s <SERVER> -t <TOKEN>\n'
printf '\n常用命令\n  nlm agent s         查看运行状态\n  nlm agent s -d      查看详细资源占用\n  nlm agent u         更新到最新版本\n  nlm agent r         重启 Agent\n  nlm agent logs -f   实时日志\n  nlm help            查看全部命令\n'
