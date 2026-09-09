# 自动化（macOS launchd）

两个 LaunchAgent 让链路全自动：

| Label | 作用 | 频率 |
|-------|------|------|
| `com.podcloud.sync` | `pod sync` 推送审计到 Pod Cloud | 每 30 分钟 + 登录时 |
| `com.podcloud.port-forward` | 常驻转发 k8s `podcloud-web` → 127.0.0.1:18088 | 常驻（KeepAlive）|
| `com.podcloud.serve` | 常驻 HTTP 网关（Streamable MCP）`http://127.0.0.1:8786/mcp`，baseline 策略 + 真实 filesystem server | 常驻（KeepAlive）|
| `com.podcloud.serve-hermes` | Hermes 网关 `http://127.0.0.1:8784/mcp`（agent=hermes） | 常驻（KeepAlive）|
| `com.podcloud.serve-openclaw` | OpenClaw 网关 `http://127.0.0.1:8783/mcp`（agent=openclaw） | 常驻（KeepAlive）|
| `com.podcloud.coverage` | `pod coverage --strict` 配置漂移检查（有未受管 server 时退出码 1） | 每小时 |
| `com.podcloud.digest` | `pod digest --out ~/.pod/digest/weekly.md` 本地安全周报 | 每周一 09:00 |

> Codex 曾配 HTTP 网关 8785，因其 rmcp 客户端只发纯 JSON Accept（被 SDK 强制
> JSON+SSE 拒绝），已切换为 stdio wrapper（`~/.pod/pod-serve-codex-stdio.sh`，
> Codex 每次会话 spawn）；但 deepseek provider + exec 模式下 Codex 不加载 MCP 工具
> （客户端侧限制）。审计目录按 agent 分：`~/.pod/audit/<agent>/`。

serve 的 agent 接入：任何支持 Streamable HTTP 的 agent 把 MCP server 配置为
`http://127.0.0.1:8786/mcp` 即可共用网关（策略/审批/审计/告警全在网关侧）。

## 漂移检查与周报

```bash
# 配置漂移：未受管 MCP server（agent 可绕过网关）会以退出码 1 告警
pod coverage --strict

# 本地安全周报（只读审计，不联网）：写入 Markdown
pod digest --since 7d --out ~/.pod/digest/weekly.md
pod digest --since 7d --json          # 机器可读
```

`pod coverage --strict` 适合挂 launchd/cron：退出码非 0 即触发告警（邮件/webhook 由你的调度器负责）。
`pod digest` 无网络依赖，报告里包含调用量、拦截、审批、敏感命中、未受管 server 与哈希链健康。

## 管理命令

```bash
# 状态
launchctl list | grep podcloud

# 手动跑一次 sync（不等待定时器）
bash ~/.pod/pod-sync.sh

# 日志
tail -20 ~/.pod/logs/sync.log          # sync 结果
tail -20 ~/.pod/logs/port-forward.err.log  # 转发错误

# 停止/启动
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.podcloud.sync.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.podcloud.sync.plist
# port-forward 同理

# 卸载（删 plist + bootout）
```

## 依赖

- `pod` 全局命令（`npm link` 于 apps/cli；代码更新后 `pnpm -r build` 即可，链接不变）
- **端口注意**：8786 供 pod serve；**8787 被 Codex gateway 占用**（com.local.codex-gateway），不要使用
- `kubectl` 在 PATH（plist 内写死 `/opt/homebrew/bin/kubectl`）
- k8s `podcloud` namespace 存在（部署见 DeepThinkHarness deploy/k8s/podcloud）

## 故障排查

- sync 日志 `fetch failed`：18088 不通 → 检查 `launchctl list | grep port-forward` 是否 exit 非 0、`kubectl get pods -n podcloud`
- 手动转发与常驻转发冲突：先 `pkill -f "port-forward svc/podcloud"` 再 bootstrap
