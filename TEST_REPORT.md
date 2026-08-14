# NodeLume v1.0.1 Final Test Report

本报告只记录本次最终打包前实际执行的测试，不把未运行的环境写成“已通过”。

## 1. 编译与静态检查

实际执行并通过：

- `gofmt`
- `go test ./...`
- `go vet ./...`
- `go test -race ./...`
- `bash -n scripts/install-server.sh scripts/install-agent.sh scripts/nlm`
- `node --check server/web/app.js`
- Linux amd64 Server / Agent / verifier 静态编译
- Linux arm64 Server / Agent / verifier 静态交叉编译
- amd64 Server / Agent `--self-check`
- amd64/arm64 ELF 架构检查
- verifier SHA256 与安装器固定 pin 一致性检查

## 2. 真实 Server + Agent 端到端测试

使用本次源码重新编译出的 amd64 二进制，使用独立临时数据目录实际启动：

- `/healthz` 正常；
- 未初始化 `/api/setup/status` 正常；
- 首次管理员密码初始化成功；
- 错误密码拒绝；
- 正确密码登录并获取 CSRF；
- 未认证访问节点 API 返回 401；
- 通用 Enrollment Token 创建成功；
- 一次性 Enrollment Token 创建成功；
- `nodelume-agent bind` 使用 HTTP 实际绑定成功并显示明文风险警告；
- Agent 配置实际写入 Node ID + Agent Secret，Enrollment Token 不再持久保留；
- 实际启动 Agent 后 Server 节点状态变为 `online`；
- Agent 实际上报 CPU/内存/磁盘/进程等数据。

## 3. HMAC / 重放 / 时钟偏差

使用真实 Enrollment 后签发的 Node ID + Agent Secret 发起请求：

- 正确 HMAC 请求成功；
- 同 Node ID + Nonce 重复请求返回 `REPLAY_DETECTED`；
- 时间偏差超过 60 秒返回 `CLOCK_SKEW`；
- Nonce 缓存实现包含过期和容量上限。

## 4. Agent 配置事务

实际测试：

- `agent set -s` 指向不可达 Server 时返回失败，原配置逐字节保持不变；
- `agent bind` 指向不可达 Server 时返回失败，原绑定逐字节保持不变。

## 5. 日志文件句柄

增加并实际运行日志 Writer 回归测试：

- Clear 时先关闭/切换 active 日志，再删除关闭的历史文件；
- 清除完成后继续向新的 `server.log` 写入；
- 大小触发 rotate 后新的 active 句柄继续可写；
- 当前 active 日志不会被历史容量清理误删。

## 6. 真实 Chromium UI 交互

最终源码通过真实 Chromium + DevTools Protocol 访问实际运行的 NodeLume Server。环境的 Chromium 原本由 URLBlocklist 禁止本地导航；测试时仅临时移除该策略，浏览器启动/测试完成后立即恢复系统策略。

22 项 UI 检查全部通过（0 failed）：

- 页面实际加载；
- 未认证时后台完全隐藏；
- 登录页不显示安全入口路径；
- 错误密码后仍保持锁定；
- 正确密码后才解锁；
- 真实 Agent 节点卡片从后端加载；
- 4 个自定义下拉组件实际生成；
- 设置窗口可打开；
- 监听未修改时保存按钮禁用；
- 修改监听后保存按钮启用；
- 改回原值后再次禁用；
- 通用 Token “有效期”自定义下拉位置/宽度正常；
- 节点详情可打开；
- Agent 自身 CPU/内存/磁盘/Inodes/RX/TX DOM 完整；
- 每次节点详情默认进入“概览”；
- 320 / 360 / 390 / 768 / 1280 px 均无页面横向溢出；
- 测试期间无未捕获 JavaScript 异常。

## 7. 未冒充实测的项目

当前环境无法等价替代以下真实外部条件，因此不标记为实机通过：

- Let's Encrypt 等真实公网 CA + 公网 DNS + 入站 TCP/80 的实际 HTTP-01 签发/续期；
- Debian、Ubuntu、CentOS 7/Stream、AlmaLinux、Rocky Linux 多台真实 systemd VPS 的完整安装/重启/升级；
- ARM64 真机执行（已完成静态交叉编译和 ELF 架构检查）；
- 长时间真实公网弱网、丢包、NAT 运行。
