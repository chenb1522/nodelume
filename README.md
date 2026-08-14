# NodeLume v1.0.1

**轻量多节点 Linux 服务器监控与管理工具**

NodeLume 由静态 Go Server、静态 Go Agent 和原生 Web UI 组成，重点是低资源占用、部署简单和严格的远程控制边界。

## 核心特性

- Linux amd64 / arm64，`CGO_ENABLED=0` 静态构建。
- Agent 仅主动连接 Server，不开放 Agent 监控端口。
- CPU、内存、磁盘、负载、网络、温度、进程、服务等监控。
- 监控历史仅保留内存 Ring Buffer，最多 1 小时。
- Agent 不提供任意 Shell、`sh -c`、任意脚本或自定义命令执行。
- 首次 Enrollment 后每台 Agent 获得独立 Node ID + Agent Secret；后续请求使用 HMAC-SHA256。
- HMAC 默认允许 ±60 秒时钟偏差；Nonce 防重放缓存有过期和容量限制。
- HTTP / HTTPS 均可使用；HTTP 会给出明文通信警告，但不会阻断。
- Server 运行日志由 NodeLume 自己滚动，不依赖 logrotate；默认保留 7 天、总容量上限 50 MiB，Web 可配置并可安全清除。
- 域名配置只保留“申请证书 / 导入证书”；自动证书使用 ACME HTTP-01。
- 管理统一使用 `nlm server ...` 和 `nlm agent ...`。

## 安装 Server

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/v1.0.1/scripts/install-server.sh | sh
```

首次无参数安装默认监听 `0.0.0.0`，自动选择当前未占用端口并持久化。重复执行同版本不会重装或重启；旧版本升级会保留配置并在启动/健康检查失败时回滚。

常用命令：

```text
nlm server s        查看运行状态
nlm server s -d     查看 NodeLume Server 自身资源占用
nlm server u        更新到最新版本
nlm server r        重启 Server
nlm server rm       卸载 Server（保留数据）
nlm server test     自检 Server
nlm help            查看完整帮助
```

## 安装 Agent

Agent 支持完全无参数安装：

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/v1.0.1/scripts/install-agent.sh | sh
```

无参数安装完成后状态为“未绑定”，之后执行：

```bash
nlm agent bind -s http://SERVER:PORT -t TOKEN
```

也可以在安装时直接绑定：

```bash
curl -fsSL https://raw.githubusercontent.com/chenb1522/nodelume/v1.0.1/scripts/install-agent.sh | sh -s -- \
  -s 'https://monitor.example.com' \
  -t 'TOKEN' \
  -n 'HK-01'
```

支持长短参数：`-s/--server`、`-t/--token`、`-n/--name`、`-v/--version`。

常用命令：

```text
nlm agent s
nlm agent s -d
nlm agent u
nlm agent r
nlm agent config
nlm agent test
nlm agent reconnect
nlm agent logs -f
nlm agent set -s URL
nlm agent set -l info
nlm agent bind -s URL -t TOKEN [-n NAME]
```

`nodelume-agent` 二进制本身也支持 `status/config/test/bind/set/version` 子命令以及运行参数；Server 二进制支持运行参数、`--version`、`--self-check`、`--pick-port` 等。

## Enrollment

Web 提供：

- 通用 Token：24 小时 / 7 天 / 30 天 / 长期，可重复接入，可撤销/重新生成。
- 指定节点 Token：一次性，默认 30 分钟。

节点名称优先级：命令行 `-n` > Web Token 预设名称 > Server 自动名称。

Enrollment Token 仅用于首次注册。注册后使用独立 Agent 身份，不再使用 Enrollment Token 进行心跳、指标和命令通信。

## 日志

Server 运行日志默认：

- 保留 7 天；
- 总容量 50 MiB；
- 内部单文件大小保护触发 rotate；
- Web 可修改保留时间和总容量；
- “清除日志”只清除运行日志，不清除审计日志；
- 实时日志使用内部事件流，历史日志读取滚动文件；
- 不依赖系统 logrotate。

## Release 安全

Release 包包含：

```text
nodelume-server-linux-amd64
nodelume-server-linux-arm64
nodelume-agent-linux-amd64
nodelume-agent-linux-arm64
nodelume-verify-linux-amd64
nodelume-verify-linux-arm64
install-server.sh
install-agent.sh
nlm
release.pub
release-manifest.json
checksums.txt
checksums.sig
```

安装器先使用固定 SHA256 引导校验静态 `nodelume-verify`，再用 Ed25519 验证 `checksums.txt`，最后验证目标文件 SHA256 和二进制 self-check。无需系统 OpenSSL 支持 Ed25519，因此兼容旧 OpenSSL 环境（例如 CentOS 7 的 OpenSSL 1.0.2 系列）。

GitHub Actions 私钥只放在 Secret：

```text
NODELUME_SIGNING_PRIVATE_KEY
```

不得提交 Release 私钥。

## 目录

```text
agent/
server/
  web/
scripts/
  install-server.sh
  install-agent.sh
  nlm
tools/
  verify/
  sign/
  keygen/
.github/workflows/release.yml
release.pub
go.mod
```

## 已知外部验收边界

本交付已在当前 Linux 构建环境实际运行 Server + Agent 端到端测试和真实 Chromium UI 交互测试。以下仍需要部署环境本身才能最终验证：真实公网域名的 CA HTTP-01 签发，以及 Debian/Ubuntu/CentOS/Alma/Rocky 各自真实 systemd VPS 的完整安装/重启测试。
