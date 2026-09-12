# 五分钟给你的 AI Agent 装上安全闸门

> 发布渠道：GitHub / 即刻 / V2EX
> 适用：OpenClaw / Claude Code / Cursor / DSH 用户

## 第 1 分钟：装

```bash
curl -fsSL https://gitee.com/suhuisoftwares/pod/raw/v0.2.0/scripts/install.sh | sh
# 主源连不上时用镜像：
# curl -fsSL https://raw.githubusercontent.com/suhui-organization/pod/v0.2.0/scripts/install.sh | sh
pod scan        # 看看你的风险面（只读、不联网）
```

> 链接钉在 v0.2.0，装到的就是发布版；想跟主干把 `v0.2.0` 换成 `main`。
> 把 `~/.local/bin` 加进 `PATH` 后（脚本会提示）即可直接用 `pod`。

## 第 2 分钟：建策略

```bash
pod init --template baseline    # 标准 OPC 基线
```

生成的策略做了四件事：未授权工具默认拒绝（fail-closed）、写操作要审批、
敏感路径（`~/.ssh`、`.env`）直接拒绝、输出里的密钥直接拦截。

同时会生成 `~/.pod/rules.json`——**判定规则归你**：阈值、正则、严重级别都在
这个文件里，改一行就换口径；写错会 fail-closed 报错，不会悄悄退回默认值。

## 第 3 分钟：接一个真实 MCP 服务器

以文件系统为例（DSH 用户直接用 `~/.dsh/mcp-manager.json`）：

```bash
pod serve --agent openclaw-main --server filesystem \
  --policy ~/.pod/policies/baseline.json \
  --command mcp-server-filesystem --arg /path/to/project
```

(`mcp-server-filesystem` 来自 `npm i -g @modelcontextprotocol/server-filesystem@2026.8.31`
——注意**钉了版本**，这正是第 1 篇说的供应链建议：别用 `@latest`，
否则下次启动跑的是别人刚上传的代码。)

想让 pod 用 npx 方式拉起？直接改成 `--command npx --arg -y --arg <包@版本>`
会被拦住——因为基线策略里声明了这个 server 的**来源白名单**：

```
[pod] fatal: Error: server "filesystem" 未通过来源白名单校验（T4）：
      source.command 不匹配：策略要求 "mcp-server-filesystem"，实际 "npx"
```

这不是阻挠，是 T4 在干活。要用 npx 就同步改策略里的 `source`：

```jsonc
// ~/.pod/policies/baseline.json
"servers": { "filesystem": { "source": { "command": "npx" }, /* …原有规则… */ } }
```

把 Agent 的 MCP 配置指向这个进程（详见 [docs/agent-onboarding.md](../agent-onboarding.md)）。

## 第 4 分钟：触发一次审批

让 agent 写文件——调用会挂起，网关提示：

```
APPROVAL NEEDED #filesystem-51234-1: server=filesystem tool=write_file
  approve: pod approve --id filesystem-51234-1 [--reason <why>]
  deny:    pod deny --id filesystem-51234-1 [--reason <why>]
```

（编号形如 `<server>-<网关进程号>-<序号>`，同一台机器跑多个网关也不会撞。
你机器上的数字会不同。）

在另一个终端批准，或直接开一个常驻审批队列：

```bash
pod watch          # 新请求立刻提示，TTY 下可直接批准/拒绝
```

不处理的话，默认 300 秒超时**按拒绝处理**（fail-closed）——**高危操作永远需要人**。

## 第 5 分钟：看审计

```bash
pod audit --tail 20
```

每条记录带 SHA-256 哈希链——改任何一条历史记录，校验立刻失败。

```
[pod] openclaw-main/filesystem.jsonl: 3 entries (chain verified, last 3)
[pod]   #   1 2026-09-12T02:56:22.631Z allow   ok      enf read_file
[pod]   #   2 2026-09-12T02:56:22.791Z approve ok      enf write_file  — manual review
[pod]   #   3 2026-09-12T02:56:22.931Z deny    blocked enf delete_file  — tool "delete_file" is denied on "filesystem"
```

`pod doctor` 还会做环境自检，并告诉你哪些 MCP 服务器**没走网关**（可被绕过）：

```
[pod] pod doctor — 环境与配置自检
[pod] ✅ 未发现绕过网关的 MCP server（受管 1 个）
```

想一次性看全（含覆盖率与哈希链健康），用 `pod digest`：它跑完会告诉你
"还有哪些 server 没被管住"。

## 之后

- `pod sync`：把审计推到 Pod Cloud（可选），跨 agent 视图 + 告警
- `pod pull-policy`：云端改策略，本地生效
- 告警：`~/.pod/alert.json` 配 webhook（企业微信/钉钉/Slack），
  密钥拦截、注入信号、deny 突增自动通知

```jsonc
// ~/.pod/alert.json
{ "webhook_url": "https://your-webhook",
  "rules": { "secret_leak": true, "injection_suspect": true,
             "deny_burst": { "threshold": 5, "window_ms": 60000 } } }
```

安全闸门不是玄学，是 5 分钟的事。
