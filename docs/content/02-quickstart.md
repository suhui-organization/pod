# 五分钟给你的 AI Agent 装上安全闸门

> 发布渠道：GitHub / 即刻 / V2EX
> 适用：OpenClaw / Claude Code / Cursor / DSH 用户

## 第 1 分钟：装

```bash
npm i -g @podsec/cli
pod scan        # 看看你的风险面（只读）
```

## 第 2 分钟：建策略

```bash
pod init --template baseline    # 标准 OPC 基线
```

生成的策略做了四件事：未授权工具默认拒绝（fail-closed）、写操作要审批、
敏感路径（`~/.ssh`、`.env`）直接拒绝、输出里的密钥直接拦截。

## 第 3 分钟：接一个真实 MCP 服务器

以文件系统为例（DSH 用户直接用 `~/.dsh/mcp-manager.json`）：

```bash
pod serve --agent openclaw-main --server filesystem \
  --policy ~/.pod/policies/baseline.json \
  --command mcp-server-filesystem --arg /path/to/project
```

把 Agent 的 MCP 配置指向这个进程（详见 [docs/agent-onboarding.md](../agent-onboarding.md)）。

## 第 4 分钟：触发一次审批

让 agent 写文件——调用会挂起，网关提示：

```
APPROVAL NEEDED #filesystem-3 ... approve: pod approve --id filesystem-3
```

在另一个终端批准（或等 300 秒自动拒绝）。**高危操作永远需要人**。

## 第 5 分钟：看审计

```bash
pod audit --tail 20
```

每条记录带 SHA-256 哈希链——改任何一条历史记录，校验立刻失败。
`pod doctor` 还会告诉你哪些 MCP 服务器还没走网关（绕过风险）。

## 之后

- `pod sync`：把审计推到 Pod Cloud（可选），跨 agent 视图 + 告警
- `pod pull-policy`：云端改策略，本地生效
- 告警：`~/.pod/alert.json` 配 webhook（企业微信/钉钉/Slack），
  密钥拦截、注入信号、deny 突增自动通知

安全闸门不是玄学，是 5 分钟的事。
