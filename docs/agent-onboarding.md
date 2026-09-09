# Agent 接入指南（Phase 0 / pod record）

目标：把你的真实 AI agent（DSH、Claude Code、OpenClaw…）的 MCP 工具调用全部经过 pod 网关，
在**不阻断任何调用**的前提下录制完整审计（哈希链、只存哈希不存原文）。

> record-only 模式：策略照常求值并写入审计（`enforced: false`），但一律放行。
> 审计文件：`~/.pod/audit/<server>.jsonl`，查看：`pod audit [--server <name>] [--tail <n>]`。

## 1. 包装一个已有 MCP server（从 dsh-mcp-manager 配置）

```bash
pod record --config ~/.dsh/mcp-manager.json --server filesystem --agent dsh-web
```

- `--config`：dsh-mcp-manager 的配置（`{ "servers": [{ name, transport, command, args, env }] }`）
- `--server`：要包装的 server 名（只支持 `stdio`，v0）
- `--agent`：给该 server 打的 agent 身份标签（用于 Asset Registry / 审计）
- 缺省策略为全 allow 标注；`--policy <file>` 可传真实策略（record 下只标注不阻断）

## 2. 把 agent 的 MCP 配置指向 pod 网关

### 2.1 DSH（dsh web，mcp-manager 管理）

mcp-manager.json 里**新增**一个条目（不要改现有条目——MEMORY：stdio 的 env/args 建后不可改，只能删了重建）：

```json
{
  "servers": [
    {
      "name": "pod-filesystem",
      "transport": "stdio",
      "command": "/Users/walden/.nvm/versions/node/v24.18.0/bin/node",
      "args": [
        "--import", "tsx",
        "/Users/walden/Workspaces/SecurityHarness/pod/apps/cli/src/index.ts",
        "record",
        "--config", "/Users/walden/.dsh/mcp-manager.json",
        "--server", "filesystem",
        "--agent", "dsh-web"
      ]
    }
  ]
}
```

要点：
- 修改后需重启 dsh web 进程；工具注册为 `mcp__pod-filesystem__*`，**仅新会话可见**
- `tsx` 的解析依赖 cwd——dsh-mcp-manager spawn 时若 cwd 不在 pod 仓库内，把 `tsx` 换成 pod 仓库内 tsx 的绝对路径
  （`/Users/walden/Workspaces/SecurityHarness/pod/node_modules/.bin/tsx`）

### 2.2 Claude Code

`~/.claude.json` 的 `mcpServers`（或项目 `.mcp.json`）新增条目：

```json
{
  "mcpServers": {
    "pod-filesystem": {
      "command": "/Users/walden/.nvm/versions/node/v24.18.0/bin/node",
      "args": [
        "--import", "tsx",
        "/Users/walden/Workspaces/SecurityHarness/pod/apps/cli/src/index.ts",
        "record",
        "--config", "/Users/walden/.dsh/mcp-manager.json",
        "--server", "filesystem",
        "--agent", "claude-code"
      ]
    }
  }
}
```

### 2.3 OpenClaw

OpenClaw 的 MCP server 配置在 agent 配置的 `mcp.servers` 下（stdio 类型），指向同一套
`node --import tsx … record …` 启动命令。本机 OpenClaw 为新版（`~/.openclaw/state/openclaw.sqlite` 存储，
无独立 config 文件），具体配置入口以 OpenClaw 官方文档为准；先用 DSH / Claude Code 路径验证，
OpenClaw 接入待其配置格式确认后补齐。

## 3. 验证

```bash
# 终端 A：起录制网关
pod record --config ~/.dsh/mcp-manager.json --server filesystem --agent claude-code

# agent 里随便调用一次文件工具（如 read_file）

# 终端 B：查看审计
pod audit --server filesystem --tail 5
# [pod] filesystem.jsonl: N entries (chain verified, last 5)
# [pod]   #   1 2026-09-01T00:00:00.000Z allow   ok      rec read_file — tool "read_file" is allowed on "filesystem" (record-only)
```

`rec` 列 = record-only（未强制）；哈希链校验失败会直接报错（防篡改）。

## 4. 隐私说明

- 审计**只存参数的 SHA-256 哈希**，不存参数/输出原文（防 T2 密钥泄露面扩大）
- 本地文件，默认无任何网络传输；Pod Cloud 同步需显式开启（v1 后期）
- record 模式不阻断任何调用——它只是"装上闸门前的取证阶段"

## 5. 当前边界（v0）

- 只支持 stdio transport（13 个 server 全部是 stdio，够用）
- 每进程包装一个 server；多 server 同时录制需多开 `pod record`
- 审批流未实现（`approve` 规则在 serve 模式下 fail-closed 阻断，record 模式不阻断）

## 6. Codex 内置工具（不走 MCP）的审计

Codex 的内置 `shell`/`exec`/`apply_patch` 工具不经过 MCP 网关，也不加载 MCP server
（例如 deepseek provider + exec 模式）。这类调用网关看不到，Pod Cloud 里会表现为
「agent online 但活跃度一直是 0」。

用 PostToolUse hook 补上：每次工具调用经 `pod ingest` 追加进同一条哈希链
（`~/.pod/audit/codex/codex-tools.jsonl`），再由 `pod sync` 上云。

```bash
python3 scripts/install-codex-hook.py           # 安装 + 信任（幂等，可重复跑）
python3 scripts/install-codex-hook.py --status  # 只查信任状态
```

> **关键点**：Codex 对非托管 hook 有 trust gate。只把命令写进 `~/.codex/hooks.json`
> 会被静默跳过。`trusted_hash` 绑定的是 hook 命令字符串，命令一变（脚本路径、参数）
> 信任即失效、活动又会归零——所以脚本路径变动后重跑一次安装器即可。

安装器通过 Codex 官方 app-server JSON-RPC（`hooks/list` + `config/batchWrite`）读写信任，
不自己复刻内部哈希算法。安装后可用 `pod audit --audit-dir ~/.pod/audit --server codex-tools`
确认事件已落链。
